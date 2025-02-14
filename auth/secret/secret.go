package secret

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// GenerateSecret generates a cryptographically secure secret for JWT signing
func GenerateSecret() ([]byte, error) {
	// Generate initial random bytes
	initialBytes := make([]byte, 64)
	if _, err := rand.Read(initialBytes); err != nil {
		return nil, fmt.Errorf("failed to generate initial random bytes: %v", err)
	}

	// Generate a random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Use PBKDF2 with SHA512 for key derivation
	iterations := 10000 // High number of iterations for better security
	derivedKey := pbkdf2.Key(initialBytes, salt, iterations, 64, sha512.New)

	// Encode as base64 and trim padding
	secret := []byte(strings.TrimRight(base64.URLEncoding.EncodeToString(derivedKey), "="))
	return secret, nil
}

// LoadOrGenerateSecret attempts to load a secret from a file, or generates and saves a new one
func LoadOrGenerateSecret(secretPath string) ([]byte, error) {
	// Try to read existing secret
	secret, err := ioutil.ReadFile(secretPath)
	if err == nil && len(secret) > 0 {
		return secret, nil
	}

	// Generate new secret
	secret, err = GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %v", err)
	}

	// Write secret to file with restricted permissions (600)
	if err := ioutil.WriteFile(secretPath, secret, 0600); err != nil {
		return nil, fmt.Errorf("failed to save JWT secret: %v", err)
	}

	return secret, nil
}
