package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateJWKThumbprint(t *testing.T) {
	t.Parallel()

	// Example from RFC 7515 Appendix A.3
	x := "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	y := "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

	got := generateJWKThumbprint(x, y)

	// Generated with:
	// 	printf '%s' '{"crv":"P-256","kty":"EC","x":"<x from RFC>","y":"<y from RFC>"}' \
	//   | openssl dgst -sha256 -binary \
	//   | openssl base64 -A \
	//   | tr '+/' '-_' | tr -d '='
	want := "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"

	if got != want {
		t.Errorf("generateJWKThumbprint(%q, %q) = %q, want %q", x, y, got, want)
	}
}

func TestPublicRoundTrip(t *testing.T) {
	t.Parallel()

	const (
		coordLen = 32
		kidLen   = 43
	)

	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	decodedX, err := base64.RawURLEncoding.DecodeString(key.Public().X)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString(%q) failed: %v", key.Public().X, err)
	}
	decodedY, err := base64.RawURLEncoding.DecodeString(key.Public().Y)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString(%q) failed: %v", key.Public().Y, err)
	}

	if len(decodedX) != coordLen {
		t.Errorf("len(decodedX) = %d, want %d", len(decodedX), coordLen)
	}
	if len(decodedY) != coordLen {
		t.Errorf("len(decodedY) = %d, want %d", len(decodedY), coordLen)
	}

	publicKeyBytes := []byte{0x04}
	publicKeyBytes = append(publicKeyBytes, decodedX...)
	publicKeyBytes = append(publicKeyBytes, decodedY...)

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKeyBytes)
	if err != nil {
		t.Fatalf("ecdsa.ParseUncompressedPublicKey(%x) failed: %v", publicKeyBytes, err)
	}

	if !publicKey.Equal(key.privateKey.Public()) {
		t.Errorf("recreated public key not equal to original public key")
	}

	if len(key.KID()) != kidLen {
		t.Errorf("len(key.KID()) = %d, want %d", len(key.KID()), kidLen)
	}

	if key.KID() != key.Public().KID {
		t.Errorf("key.KID() = %q, want %q", key.KID(), key.Public().KID)
	}

	if strings.ContainsAny(key.KID(), "=+/") {
		t.Errorf("key.KID() = %q, contains '=' or '+' or '/'", key.KID())
	}
}
