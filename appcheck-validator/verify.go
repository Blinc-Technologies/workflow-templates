package main

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

var errNoMatchingKey = errors.New("no matching key found in jwks")

// jwkToRSAPublicKey converts a JWK's base64url-encoded modulus and exponent
// into an *rsa.PublicKey usable for RS256 signature verification.
func jwkToRSAPublicKey(key JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

// verifyToken validates a Firebase App Check token's RS256 signature against
// the cached JWKS and checks standard claims (exp, iss, aud). It returns the
// token's subject, which Firebase App Check sets to the Firebase App ID.
func verifyToken(token string, jwks JWKS, projectNumber string) (string, error) {
	expectedIssuer := "https://firebaseappcheck.googleapis.com/" + projectNumber
	expectedAudience := "projects/" + projectNumber

	var unknownKid bool

	keyfunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("token missing kid header")
		}

		for _, key := range jwks.Keys {
			if key.Kid == kid {
				return jwkToRSAPublicKey(key)
			}
		}
		unknownKid = true
		return nil, errNoMatchingKey
	}

	claims := jwt.RegisteredClaims{}
	parsed, err := jwt.ParseWithClaims(token, &claims, keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(expectedIssuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		// Reported directly (rather than relying on how the jwt library
		// wraps the keyfunc's error) so callers can reliably detect this
		// case with errors.Is and trigger a JWKS refresh-and-retry.
		if unknownKid {
			return "", fmt.Errorf("token validation failed: %w", errNoMatchingKey)
		}
		return "", fmt.Errorf("token validation failed: %w", err)
	}
	if !parsed.Valid {
		return "", errors.New("token invalid")
	}
	if claims.Subject == "" {
		return "", errors.New("token missing subject")
	}

	return claims.Subject, nil
}
