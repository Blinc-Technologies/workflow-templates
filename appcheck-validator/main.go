package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type keyCache struct {
	mu          sync.RWMutex
	jwks        JWKS
	lastRefresh time.Time
}

func (c *keyCache) get() JWKS {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.jwks
}

const defaultJWKSURL = "https://firebaseappcheck.googleapis.com/v1/jwks"

// unknownKidCooldown bounds how often an unrecognized kid can trigger an
// unscheduled refresh, so a flood of tokens with bogus kids can't be used
// to hammer the JWKS endpoint.
const unknownKidCooldown = time.Minute

func (c *keyCache) refresh(jwksURL string) error {
	// Set before the fetch so a failing/unreachable endpoint is also
	// subject to the cooldown, not just successful refreshes.
	c.mu.Lock()
	c.lastRefresh = time.Now()
	c.mu.Unlock()

	resp, err := http.Get(jwksURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	c.mu.Lock()
	c.jwks = jwks
	c.mu.Unlock()
	return nil
}

// refreshIfDue refreshes the cache only if at least minInterval has passed
// since the last refresh (scheduled or reactive). Returns an error if the
// cooldown is still active, so callers know a refresh did not happen.
func (c *keyCache) refreshIfDue(jwksURL string, minInterval time.Duration) error {
	c.mu.RLock()
	due := time.Since(c.lastRefresh) >= minInterval
	c.mu.RUnlock()
	if !due {
		return errors.New("refresh skipped: cooldown active")
	}
	return c.refresh(jwksURL)
}

// validateHandler checks the X-Firebase-AppCheck header. If the token's kid
// isn't in the cached JWKS, it triggers one on-demand refresh (subject to
// unknownKidCooldown) and retries, rather than waiting for the next
// scheduled refresh and rejecting a token signed with a newly rotated-in key.
//
// If disabled is true, every request is let through without checking the
// token at all. This is an emergency bypass switch (APPCHECK_DISABLED=true)
// and is intentionally loud about being active: it marks every bypassed
// response so it's never silently indistinguishable from a real pass.
func validateHandler(cache *keyCache, jwksURL, projectNumber string, disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		elapsedMs := func() int64 { return time.Since(start).Milliseconds() }

		// Traefik's forwardAuth (trustForwardHeader: true) sets these to
		// describe the original request being gated, not this call itself.
		host := r.Header.Get("X-Forwarded-Host")
		uri := r.Header.Get("X-Forwarded-Uri")

		if disabled {
			log.Printf("BYPASS host=%q uri=%q duration_ms=%d", host, uri, elapsedMs())
			w.Header().Set("X-Firebase-App-Id", "bypassed")
			w.WriteHeader(http.StatusOK)
			return
		}

		token := r.Header.Get("X-Firebase-AppCheck")
		if token == "" {
			log.Printf("DENY host=%q uri=%q reason=missing_token duration_ms=%d", host, uri, elapsedMs())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		appID, err := verifyToken(token, cache.get(), projectNumber)
		if errors.Is(err, errNoMatchingKey) {
			if refreshErr := cache.refreshIfDue(jwksURL, unknownKidCooldown); refreshErr == nil {
				log.Printf("INFO host=%q uri=%q unrecognized kid, refreshed JWKS and retrying, duration_ms_so_far=%d", host, uri, elapsedMs())
				appID, err = verifyToken(token, cache.get(), projectNumber)
			}
		}
		if err != nil {
			// Never log the full token - it's a bearer credential. A short
			// prefix (just the JWT header, not the signature or claims) is
			// enough to correlate repeated failures without exposing it.
			log.Printf("DENY host=%q uri=%q reason=%q token_prefix=%s duration_ms=%d", host, uri, err.Error(), tokenPrefix(token), elapsedMs())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		log.Printf("ALLOW host=%q uri=%q app_id=%s duration_ms=%d", host, uri, appID, elapsedMs())
		w.Header().Set("X-Firebase-App-Id", appID)
		w.WriteHeader(http.StatusOK)
	}
}

func tokenPrefix(token string) string {
	const n = 12
	if len(token) <= n {
		return token
	}
	return token[:n] + "..."
}

func main() {
	projectNumber := os.Getenv("FIREBASE_PROJECT_NUMBER")
	if projectNumber == "" {
		log.Fatal("FIREBASE_PROJECT_NUMBER must be set")
	}

	jwksURL := os.Getenv("FIREBASE_JWKS_URL")
	if jwksURL == "" {
		jwksURL = defaultJWKSURL
	}

	disabled := os.Getenv("APPCHECK_DISABLED") == "true"
	if disabled {
		log.Print("WARNING: APPCHECK_DISABLED=true - App Check verification is bypassed, every request will be allowed through unchecked")
	}

	cache := &keyCache{}

	if !disabled {
		// Fetch once synchronously before serving traffic, never block a live request on this later
		if err := cache.refresh(jwksURL); err != nil {
			log.Fatalf("initial JWKS fetch failed: %v", err)
		}

		go func() {
			ticker := time.NewTicker(6 * time.Hour)
			for range ticker.C {
				if err := cache.refresh(jwksURL); err != nil {
					log.Printf("background JWKS refresh failed: %v", err)
				}
			}
		}()
	}

	http.HandleFunc("/validate", validateHandler(cache, jwksURL, projectNumber, disabled))

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:         ":8090",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
