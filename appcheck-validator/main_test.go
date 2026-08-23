package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func jwkFromTestKey(kid string, key *rsa.PrivateKey) JWK {
	return JWK{
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

func encodeJWKS(t *testing.T, w http.ResponseWriter, jwks JWKS) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		t.Fatalf("encode jwks: %v", err)
	}
}

func TestValidateHandler_UnknownKidTriggersRefreshAndRetry(t *testing.T) {
	oldKey := mustGenerateKey(t)
	newKey := mustGenerateKey(t)

	var hits int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		jwks := JWKS{Keys: []JWK{
			jwkFromTestKey("old-kid", oldKey),
			jwkFromTestKey("new-kid", newKey),
		}}
		encodeJWKS(t, w, jwks)
	}))
	defer jwksServer.Close()

	cache := &keyCache{jwks: JWKS{Keys: []JWK{jwkFromTestKey("old-kid", oldKey)}}}
	handler := validateHandler(cache, jwksServer.URL, testProjectNumber, false)

	token := signToken(t, newKey, validOpts("new-kid"))
	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	req.Header.Set("X-Firebase-AppCheck", token)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after refresh-and-retry, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Firebase-App-Id"); got == "" {
		t.Fatal("expected X-Firebase-App-Id header to be set")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch, got %d", hits)
	}
}

func TestValidateHandler_UnknownKidCooldownLimitsRefreshRate(t *testing.T) {
	oldKey := mustGenerateKey(t)
	attackerKey := mustGenerateKey(t)

	var hits int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		jwks := JWKS{Keys: []JWK{jwkFromTestKey("old-kid", oldKey)}}
		encodeJWKS(t, w, jwks)
	}))
	defer jwksServer.Close()

	cache := &keyCache{jwks: JWKS{Keys: []JWK{jwkFromTestKey("old-kid", oldKey)}}}
	handler := validateHandler(cache, jwksServer.URL, testProjectNumber, false)

	token := signToken(t, attackerKey, validOpts("bogus-kid"))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/validate", nil)
		req.Header.Set("X-Firebase-AppCheck", token)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d: expected 401, got %d", i, rec.Code)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected cooldown to limit refreshes to 1 across 5 requests, got %d", got)
	}
}

func TestValidateHandler_KnownKidNeverTriggersRefresh(t *testing.T) {
	key := mustGenerateKey(t)

	var hits int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		encodeJWKS(t, w, JWKS{Keys: []JWK{jwkFromTestKey("kid-1", key)}})
	}))
	defer jwksServer.Close()

	cache := &keyCache{jwks: JWKS{Keys: []JWK{jwkFromTestKey("kid-1", key)}}}
	handler := validateHandler(cache, jwksServer.URL, testProjectNumber, false)

	token := signToken(t, key, validOpts("kid-1"))
	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	req.Header.Set("X-Firebase-AppCheck", token)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("expected no JWKS fetch for a known kid, got %d", got)
	}
}

func TestRefreshIfDue_RespectsCooldown(t *testing.T) {
	key := mustGenerateKey(t)
	var hits int32
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		encodeJWKS(t, w, JWKS{Keys: []JWK{jwkFromTestKey("kid-1", key)}})
	}))
	defer jwksServer.Close()

	cache := &keyCache{}

	if err := cache.refreshIfDue(jwksServer.URL, time.Hour); err != nil {
		t.Fatalf("expected first refresh to run, got error: %v", err)
	}
	if err := cache.refreshIfDue(jwksServer.URL, time.Hour); err == nil {
		t.Fatal("expected second refresh to be blocked by cooldown")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 fetch, got %d", got)
	}
}

func TestValidateHandler_DisabledBypassesVerificationEntirely(t *testing.T) {
	// An empty cache and no token at all: if the bypass didn't actually
	// short-circuit verification, this would fail for lack of any key.
	cache := &keyCache{}
	handler := validateHandler(cache, "http://unused.invalid", testProjectNumber, true)

	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 while disabled, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Firebase-App-Id"); got != "bypassed" {
		t.Fatalf("expected bypassed marker header, got %q", got)
	}
}
