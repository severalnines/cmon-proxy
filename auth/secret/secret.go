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

func GenerateSecret() ([]byte, error) {
	initialBytes := make([]byte, 64)
	if _, err := rand.Read(initialBytes); err != nil {
		return nil, fmt.Errorf("failed to generate initial random bytes: %v", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	iterations := 10000 // High number of iterations for better security
	derivedKey := pbkdf2.Key(initialBytes, salt, iterations, 64, sha512.New)

	secret := []byte(strings.TrimRight(base64.URLEncoding.EncodeToString(derivedKey), "="))
	return secret, nil
}

func LoadOrGenerateSecret(secretPath string) ([]byte, error) {
	secret, err := ioutil.ReadFile(secretPath)
	if err == nil && len(secret) > 0 {
		return secret, nil
	}

	secret, err = GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %v", err)
	}

	if err := ioutil.WriteFile(secretPath, secret, 0600); err != nil {
		return nil, fmt.Errorf("failed to save JWT secret: %v", err)
	}

	return secret, nil
}
