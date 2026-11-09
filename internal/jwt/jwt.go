// Package jwt provides a JWT implementation.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

type HeaderType string

const (
	HeaderTypeAccessToken HeaderType = "at+jwt"
)

type Header struct {
	Alg string     `json:"alg"`
	KID string     `json:"kid"`
	Typ HeaderType `json:"typ"`
}

type RegisteredClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	// RFC 7519 §4.1.3 allows the array form even for a single audience, though it is not usual.
	// TODO: use a string instead of an array when it's a single audience.
	Aud []string `json:"aud"`
	Exp int64    `json:"exp"`
	Iat int64    `json:"iat"`
	Jti string   `json:"jti"`
}

type AccessTokenClaims struct {
	RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

// New creates a new signed JWT.
func New(key *jwk.Key, typ HeaderType, claims any) (string, error) {
	header := Header{
		Alg: key.Alg(),
		KID: key.KID(),
		Typ: typ,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	combinedEncodedBytes := base64.RawURLEncoding.AppendEncode(nil, headerBytes)
	combinedEncodedBytes = append(combinedEncodedBytes, '.')
	combinedEncodedBytes = base64.RawURLEncoding.AppendEncode(combinedEncodedBytes, claimsBytes)

	signature, err := key.Sign(combinedEncodedBytes)
	if err != nil {
		return "", fmt.Errorf("sign new token: %w", err)
	}

	combinedEncodedBytes = append(combinedEncodedBytes, '.')
	combinedEncodedBytes = base64.RawURLEncoding.AppendEncode(combinedEncodedBytes, signature)

	return string(combinedEncodedBytes), nil
}
