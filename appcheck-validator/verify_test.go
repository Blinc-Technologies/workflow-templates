package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testProjectNumber = "1234567890"

func mustGenerateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

func jwkFromKey(kid string, key *rsa.PrivateKey) JWK {
	return JWK{
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}
}

type tokenOpts struct {
	kid       string
	issuer    string
	audience  string
	subject   string
	expiresAt time.Time
	notBefore time.Time
	alg       string
}

func signToken(t *testing.T, key *rsa.PrivateKey, opts tokenOpts) string {
	t.Helper()

	claims := jwt.RegisteredClaims{
		Issuer:    opts.issuer,
		Audience:  jwt.ClaimStrings{opts.audience},
		Subject:   opts.subject,
		ExpiresAt: jwt.NewNumericDate(opts.expiresAt),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if opts.kid != "" {
		token.Header["kid"] = opts.kid
	}

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func validOpts(kid string) tokenOpts {
	return tokenOpts{
		kid:       kid,
		issuer:    "https://firebaseappcheck.googleapis.com/" + testProjectNumber,
		audience:  "projects/" + testProjectNumber,
		subject:   "1:1234567890:ios:abcdef123456",
		expiresAt: time.Now().Add(time.Hour),
	}
}

func TestVerifyToken_Valid(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	token := signToken(t, key, validOpts("kid-1"))

	appID, err := verifyToken(token, jwks, testProjectNumber)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if appID != "1:1234567890:ios:abcdef123456" {
		t.Fatalf("unexpected app id: %s", appID)
	}
}

func TestVerifyToken_Expired(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	opts := validOpts("kid-1")
	opts.expiresAt = time.Now().Add(-time.Hour)
	token := signToken(t, key, opts)

	if _, err := verifyToken(token, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestVerifyToken_WrongIssuer(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	opts := validOpts("kid-1")
	opts.issuer = "https://evil.example.com/" + testProjectNumber
	token := signToken(t, key, opts)

	if _, err := verifyToken(token, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
}

func TestVerifyToken_WrongAudience(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	opts := validOpts("kid-1")
	opts.audience = "projects/other-project"
	token := signToken(t, key, opts)

	if _, err := verifyToken(token, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
}

func TestVerifyToken_UnknownKid(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	token := signToken(t, key, validOpts("kid-does-not-exist"))

	if _, err := verifyToken(token, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for unknown kid, got nil")
	}
}

func TestVerifyToken_MissingKid(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	token := signToken(t, key, validOpts(""))

	if _, err := verifyToken(token, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for missing kid, got nil")
	}
}

func TestVerifyToken_WrongSigningKey(t *testing.T) {
	signingKey := mustGenerateKey(t)
	otherKey := mustGenerateKey(t)
	// JWKS only knows about otherKey's public key, not signingKey's.
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", otherKey)}}

	token := signToken(t, signingKey, validOpts("kid-1"))

	if _, err := verifyToken(token, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for signature mismatch, got nil")
	}
}

func TestVerifyToken_MalformedToken(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	malformed := []string{
		"",
		"not-a-jwt",
		"a.b.c.d",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.",
	}

	for _, tok := range malformed {
		if _, err := verifyToken(tok, jwks, testProjectNumber); err == nil {
			t.Fatalf("expected error for malformed token %q, got nil", tok)
		}
	}
}

func TestVerifyToken_NoneAlgorithmRejected(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	claims := jwt.RegisteredClaims{
		Issuer:    "https://firebaseappcheck.googleapis.com/" + testProjectNumber,
		Audience:  jwt.ClaimStrings{"projects/" + testProjectNumber},
		Subject:   "1:1234567890:ios:abcdef123456",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	token.Header["kid"] = "kid-1"
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none-alg token: %v", err)
	}

	if _, err := verifyToken(unsigned, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for alg=none token, got nil")
	}
}

func TestVerifyToken_MissingSubject(t *testing.T) {
	key := mustGenerateKey(t)
	jwks := JWKS{Keys: []JWK{jwkFromKey("kid-1", key)}}

	opts := validOpts("kid-1")
	opts.subject = ""
	token := signToken(t, key, opts)

	if _, err := verifyToken(token, jwks, testProjectNumber); err == nil {
		t.Fatal("expected error for missing subject, got nil")
	}
}
