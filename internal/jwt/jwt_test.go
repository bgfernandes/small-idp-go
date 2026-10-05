package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scope      string
		wantClaims string
	}{
		{
			name:       "without scope",
			scope:      "",
			wantClaims: `{"iss":"issuer","sub":"subject","aud":"audience","exp":1,"iat":2,"jti":"json web token id","client_id":"client-id"}`,
		},
		{
			name:       "with scope",
			scope:      "read write",
			wantClaims: `{"iss":"issuer","sub":"subject","aud":"audience","exp":1,"iat":2,"jti":"json web token id","client_id":"client-id","scope":"read write"}`,
		},
	}

	key, err := jwk.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			claims := AccessTokenClaims{
				Iss:      "issuer",
				Sub:      "subject",
				Aud:      "audience",
				Exp:      1,
				Iat:      2,
				Jti:      "json web token id",
				ClientID: "client-id",
				Scope:    tt.scope,
			}

			token, err := New(key, "some-type", claims)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			// Check shape
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Fatalf("len(parts) = %d, want 3", len(parts))
			}

			// For each part, check encoding and decode
			decodedParts := make([]string, len(parts))
			for i, part := range parts {
				decoded, err := base64.RawURLEncoding.DecodeString(part)
				if err != nil {
					t.Fatalf("DecodeString() failed: %v", err)
				}
				decodedParts[i] = string(decoded)
			}

			// Check header format
			var header Header
			err = json.Unmarshal([]byte(decodedParts[0]), &header)
			if err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}
			if header.Alg != key.Alg() {
				t.Fatalf("header.Alg = %q, want %q", header.Alg, key.Alg())
			}
			if header.KID != key.KID() {
				t.Fatalf("header.KID = %q, want %q", header.KID, key.KID())
			}
			if header.Typ != "some-type" {
				t.Fatalf("header.Typ = %q, want %q", header.Typ, "some-type")
			}

			// Check claims
			if decodedParts[1] != tt.wantClaims {
				t.Fatalf("decodedParts[1] = %q, want %q", decodedParts[1], tt.wantClaims)
			}

			// Check signature length
			if len(decodedParts[2]) != 64 {
				t.Fatalf("len(decodedParts[2]) = %d, want 64", len(decodedParts[2]))
			}
		})
	}
}

func TestNewMarshalError(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Unmarshable claims return an error and an empty string
	unmarshableClaims := make(chan int)
	token, err := New(key, "some-type", unmarshableClaims)
	if err == nil {
		t.Fatalf("New() should have returned an error")
	}
	if token != "" {
		t.Fatalf("token = %q, want empty string", token)
	}
}
