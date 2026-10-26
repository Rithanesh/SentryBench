// Package jwtutil implements the JWT Inspector's backend logic: decoding
// without verification (so malformed/expired tokens still display), plus
// opt-in signature verification and a weak-secret dictionary check for
// authorized testing. Nothing here persists a secret — callers decide
// whether to save one to the encrypted identity vault.
package jwtutil

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Decoded struct {
	Header         map[string]interface{} `json:"header"`
	Payload        map[string]interface{} `json:"payload"`
	Signature      string                  `json:"signature"`
	Algorithm      string                  `json:"algorithm"`
	IsExpired      bool                    `json:"isExpired"`
	IsNotYetValid  bool                    `json:"isNotYetValid"`
	ExpiresAt      *time.Time              `json:"expiresAt,omitempty"`
	NotBefore      *time.Time              `json:"notBefore,omitempty"`
	IssuedAt       *time.Time              `json:"issuedAt,omitempty"`
	Warnings       []string                `json:"warnings"`
}

// Decode parses a JWT's three segments without verifying the signature.
func Decode(token string) (Decoded, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return Decoded{}, fmt.Errorf("not a JWT: expected at least 2 dot-separated segments")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Decoded{}, fmt.Errorf("invalid header encoding: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Decoded{}, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var header, payload map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Decoded{}, fmt.Errorf("invalid header JSON: %w", err)
	}
	_ = json.Unmarshal(payloadBytes, &payload) // payload may legitimately be empty/non-object

	d := Decoded{Header: header, Payload: payload}
	if len(parts) >= 3 {
		d.Signature = parts[2]
	}
	if alg, ok := header["alg"].(string); ok {
		d.Algorithm = alg
	}

	now := time.Now()
	if exp, ok := numericClaim(payload, "exp"); ok {
		t := time.Unix(exp, 0)
		d.ExpiresAt = &t
		d.IsExpired = now.After(t)
	}
	if nbf, ok := numericClaim(payload, "nbf"); ok {
		t := time.Unix(nbf, 0)
		d.NotBefore = &t
		d.IsNotYetValid = now.Before(t)
	}
	if iat, ok := numericClaim(payload, "iat"); ok {
		t := time.Unix(iat, 0)
		d.IssuedAt = &t
	}

	d.Warnings = warningsFor(d.Algorithm, d.Signature)
	return d, nil
}

func warningsFor(alg, signature string) []string {
	var warnings []string
	switch strings.ToLower(alg) {
	case "none":
		warnings = append(warnings, "alg is \"none\" — this token requires no valid signature and must never be trusted as-is.")
	case "":
		warnings = append(warnings, "No alg present in header.")
	}
	if signature == "" {
		warnings = append(warnings, "Token has no signature segment.")
	}
	return warnings
}

func numericClaim(payload map[string]interface{}, key string) (int64, bool) {
	v, ok := payload[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

// VerifyResult is returned by HMAC/RSA/ECDSA verification.
type VerifyResult struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// VerifyHMAC checks an HS256/HS384/HS512 signature against a user-supplied secret.
func VerifyHMAC(token, secret string) VerifyResult {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("token does not use an HMAC algorithm (got %v)", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return VerifyResult{Valid: false, Error: err.Error()}
	}
	return VerifyResult{Valid: true}
}

// VerifyRSA checks an RS256/RS384/RS512 signature against a PEM public key.
func VerifyRSA(token string, publicKey *rsa.PublicKey) VerifyResult {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("token does not use an RSA algorithm (got %v)", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return VerifyResult{Valid: false, Error: err.Error()}
	}
	return VerifyResult{Valid: true}
}

// VerifyECDSA checks an ES256/ES384/ES512 signature against a PEM public key.
func VerifyECDSA(token string, publicKey *ecdsa.PublicKey) VerifyResult {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("token does not use an ECDSA algorithm (got %v)", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return VerifyResult{Valid: false, Error: err.Error()}
	}
	return VerifyResult{Valid: true}
}

// WeakSecretResult reports whether any candidate in a user-supplied wordlist
// successfully verifies the token's HMAC signature. This is explicitly an
// authorized-testing feature: it never runs automatically, only on request,
// and the caller must already have the token in hand.
type WeakSecretResult struct {
	Cracked   bool   `json:"cracked"`
	Secret    string `json:"secret,omitempty"`
	Attempted int    `json:"attempted"`
}

func CheckWeakSecret(token string, candidates []string) WeakSecretResult {
	for i, candidate := range candidates {
		if VerifyHMAC(token, candidate).Valid {
			return WeakSecretResult{Cracked: true, Secret: candidate, Attempted: i + 1}
		}
	}
	return WeakSecretResult{Cracked: false, Attempted: len(candidates)}
}
