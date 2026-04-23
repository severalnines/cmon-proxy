package rpcserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCA(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestBuildClientTLS_AllowsCAOnly(t *testing.T) {
	caPath := writeTestCA(t)
	creds, err := buildClientTLS("", "", caPath)
	if err != nil {
		t.Fatalf("buildClientTLS() error = %v", err)
	}
	if creds == nil {
		t.Fatal("buildClientTLS() returned nil credentials")
	}
}

func TestBuildClientTLS_RequiresClientCertPairTogether(t *testing.T) {
	caPath := writeTestCA(t)
	if _, err := buildClientTLS("/tmp/client.crt", "", caPath); err == nil {
		t.Fatal("buildClientTLS() error = nil, want missing-key error")
	}
	if _, err := buildClientTLS("", "/tmp/client.key", caPath); err == nil {
		t.Fatal("buildClientTLS() error = nil, want missing-cert error")
	}
}
