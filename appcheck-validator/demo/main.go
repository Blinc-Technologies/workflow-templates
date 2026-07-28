// Standalone demo: runs a fake JWKS server on :9999 and prints a valid and
// an expired Firebase App Check-shaped token, plus curl commands to try
// against the real service. Not part of the production build.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	demoProjectNumber = "1234567890"
	demoAppID         = "1:1234567890:ios:abcdef123456"
	demoKid           = "demo-kid-1"
)

type jwk struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func signToken(key *rsa.PrivateKey, expiresAt time.Time) string {
	claims := jwt.RegisteredClaims{
		Issuer:    "https://firebaseappcheck.googleapis.com/" + demoProjectNumber,
		Audience:  jwt.ClaimStrings{"projects/" + demoProjectNumber},
		Subject:   demoAppID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = demoKid

	signed, err := token.SignedString(key)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}
	return signed
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate rsa key: %v", err)
	}

	jwks := struct {
		Keys []jwk `json:"keys"`
	}{
		Keys: []jwk{{
			Kid: demoKid,
			N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	}

	http.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	validToken := signToken(key, time.Now().Add(time.Hour))
	expiredToken := signToken(key, time.Now().Add(-time.Hour))

	fmt.Println("Fake JWKS server starting on http://localhost:9999/jwks")
	fmt.Println()
	fmt.Println("In another terminal, run the real service against this fake JWKS:")
	fmt.Println()
	fmt.Printf("  FIREBASE_PROJECT_NUMBER=%s FIREBASE_JWKS_URL=http://localhost:9999/jwks go run .\n", demoProjectNumber)
	fmt.Println()
	fmt.Println("Then, in a third terminal:")
	fmt.Println()
	fmt.Println("  # no token -> 401")
	fmt.Println("  curl -i localhost:8080/validate")
	fmt.Println()
	fmt.Println("  # valid token -> 200 + X-Firebase-App-Id header")
	fmt.Printf("  curl -i localhost:8080/validate -H \"X-Firebase-AppCheck: %s\"\n", validToken)
	fmt.Println()
	fmt.Println("  # expired token -> 401")
	fmt.Printf("  curl -i localhost:8080/validate -H \"X-Firebase-AppCheck: %s\"\n", expiredToken)
	fmt.Println()

	log.Fatal(http.ListenAndServe(":9999", nil))
}
