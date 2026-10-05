// Package jwk implements the JWK (JSON Web Key) format for the small IDP.
package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	alg = "ES256"
	crv = "P-256"
	kty = "EC"
	use = "sig"
)

// Key is the internal key type, used for signing and verifying JWTs.
// Currently it can hold only one key pair for the ES256 algorithm.
type Key struct {
	public     PublicKey
	privateKey *ecdsa.PrivateKey
}

// PublicKey is the JWK representation (RFC 7517 §4, RFC 7518 §6.2) of a public key, as published in the JWKS.
type PublicKey struct {
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	KID string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Set is the JWK Set representation (RFC 7517 §5) of a set of public keys.
type Set struct {
	Keys []PublicKey `json:"keys"`
}

// Alg returns the algorithm of the key pair.
func (k *Key) Alg() string {
	return k.public.Alg
}

// KID returns the key identifier of the key pair.
func (k *Key) KID() string {
	return k.public.KID
}

// Public returns the JWK representation of the public key of the key pair.
func (k *Key) Public() PublicKey {
	return k.public
}

// Sign hashes the given data and signs it with the private key of the key pair.
func (k *Key) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, k.privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// the signature is the concatenation of the R and S values, each 32 bytes long, as per RFC 7518 §3.4
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

// Generate generates a new JWK for the ES256 algorithm only, for now.
func Generate() (*Key, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	public, err := generatePublic(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("generate public: %w", err)
	}

	return &Key{
		public:     public,
		privateKey: key,
	}, nil
}

func generatePublic(publicKey *ecdsa.PublicKey) (PublicKey, error) {
	publicKeyBytes, err := publicKey.Bytes()
	if err != nil {
		return PublicKey{}, fmt.Errorf("get public key bytes: %w", err)
	}

	// the X and Y coordinates according to RFC 7518 §6.2.1.2
	// SEC 1 uncompressed format is 0x04, then X, then Y, 32 bytes each for P-256
	// unpadded base64url according to RFC 7515 §2
	x := base64.RawURLEncoding.EncodeToString(publicKeyBytes[1:33])
	y := base64.RawURLEncoding.EncodeToString(publicKeyBytes[33:65])

	return PublicKey{
		Alg: alg,
		Crv: crv,
		KID: generateJWKThumbprint(x, y),
		Kty: kty,
		Use: use,
		X:   x,
		Y:   y,
	}, nil
}

func generateJWKThumbprint(x, y string) string {
	// thumbprint construction according to RFC 7638 §3
	jwkJSON, err := json.Marshal(map[string]string{
		"crv": crv,
		"kty": kty,
		"x":   x,
		"y":   y,
	})

	if err != nil {
		panic(err)
	}

	thumbprint := sha256.Sum256(jwkJSON)
	// unpadded base64url according to RFC 7515 §2
	return base64.RawURLEncoding.EncodeToString(thumbprint[:])
}
