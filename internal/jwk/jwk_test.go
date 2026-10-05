package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
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

func TestSign(t *testing.T) {
	t.Parallel()

	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	differentKey, err := Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "small message",
			message: []byte("small"),
		},
		{
			name:    "empty message",
			message: []byte(""),
		},
		{
			name:    "large message",
			message: make([]byte, 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signature, err := key.Sign(tt.message)
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}

			// Length check
			if len(signature) != 64 {
				t.Fatalf("len(signature) = %d, want 64", len(signature))
			}

			// Verify signature
			r := new(big.Int).SetBytes(signature[:32])
			s := new(big.Int).SetBytes(signature[32:])
			digest := sha256.Sum256(tt.message)
			if !ecdsa.Verify(&key.privateKey.PublicKey, digest[:], r, s) {
				t.Fatalf("Verify() failed")
			}

			// Verify different message fails
			differentMessage := append(tt.message, 1) // Add one byte
			differentDigest := sha256.Sum256(differentMessage)
			if ecdsa.Verify(&key.privateKey.PublicKey, differentDigest[:], r, s) {
				t.Fatalf("Verify() should have failed")
			}

			// Verify with different key fails
			if ecdsa.Verify(&differentKey.privateKey.PublicKey, digest[:], r, s) {
				t.Fatalf("Verify() should have failed")
			}
		})
	}

}
