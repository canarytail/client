package canarytail

import (
	"crypto/ed25519"
	"encoding/base64"
	"math/rand"
	"time"

	"golang.org/x/crypto/curve25519"
)

// SignString signs a Canary given a private key
func SignString(formattedCanary string, privateKey ed25519.PrivateKey) []byte {
	message := []byte(formattedCanary)
	return ed25519.Sign(privateKey, message)
}

// ValidateSignatureString validates a Canary's signature given the corresponding public key
func ValidateSignatureString(formattedCanary string, signature []byte, publicKey ed25519.PublicKey) bool {
	message := []byte(formattedCanary)
	return ed25519.Verify(publicKey, message, signature)
}

// deprecated: curve25519 vs ed25519
func generateRandomPrivateKey() [32]byte {
	rand.Seed(time.Now().UnixNano())

	var privateKey [32]byte
	for i := range privateKey[:] {
		privateKey[i] = byte(rand.Intn(256))
	}
	return privateKey
}

// depracated: curve25519 vs ed25519
func generatePublicKey(privateKey [32]byte) [32]byte {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

// GenerateKeyPair generates an Ed25519 key pair for signatures. See https://ed25519.cr.yp.to/.
//
// These functions are also compatible with the “Ed25519” function defined in RFC 8032.
// However, unlike RFC 8032's formulation, this package's private key representation
// includes a public key suffix to make multiple signing operations with the same key more efficient.
// This package refers to the RFC 8032 private key as the “seed”.
//
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// ParsePublicKey parses a public key in string form
func ParsePublicKey(publicKey string) (ed25519.PublicKey, error) {
	return base64.StdEncoding.DecodeString(publicKey)
}

// ParsePrivateKey parses a private key in string form
func ParsePrivateKey(privateKey string) (ed25519.PrivateKey, error) {
	return base64.StdEncoding.DecodeString(privateKey)
}

// FormatKey formats a key into a base64 string
func FormatKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}
