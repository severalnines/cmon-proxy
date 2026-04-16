package metering

// Copyright 2026 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SealResult holds the output of sealing a report.
type SealResult struct {
	CanonicalJSON string
	SHA256Hash    string
	Signature     string
	SigningKeyID  string
}

// SealReport seals a ReportData by computing its canonical JSON, SHA-256 hash,
// and HMAC-SHA256 signature.
func SealReport(report *ReportData, signingKey []byte, signingKeyID string) (*SealResult, error) {
	canonical, err := CanonicalJSON(report)
	if err != nil {
		return nil, fmt.Errorf("canonical json: %w", err)
	}

	hash := ComputeSHA256(canonical)

	signature := ""
	if len(signingKey) > 0 {
		signature = ComputeHMAC(hash, signingKey)
	}

	return &SealResult{
		CanonicalJSON: canonical,
		SHA256Hash:    hash,
		Signature:     signature,
		SigningKeyID:  signingKeyID,
	}, nil
}

// VerifySeal recomputes the hash and signature from stored report data
// and compares them to the stored values.
func VerifySeal(reportData string, storedHash string, storedSignature string, signingKey []byte) (hashValid bool, signatureValid bool) {
	computedHash := ComputeSHA256(reportData)
	hashValid = computedHash == storedHash

	if len(signingKey) > 0 && storedSignature != "" {
		computedSig := ComputeHMAC(computedHash, signingKey)
		signatureValid = hmac.Equal([]byte(computedSig), []byte(storedSignature))
	} else if storedSignature == "" && len(signingKey) == 0 {
		// No signature expected, no key — signature is trivially valid.
		signatureValid = true
	}

	return hashValid, signatureValid
}

// CanonicalJSON produces a deterministic JSON serialization of a value.
// Keys are sorted and no extraneous whitespace is added.
// This uses json.Marshal which sorts map keys by default, and struct fields
// are ordered by their declaration order (which is deterministic).
func CanonicalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ComputeSHA256 returns the hex-encoded SHA-256 hash of the given string.
func ComputeSHA256(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ComputeHMAC returns the hex-encoded HMAC-SHA256 of the given data using the given key.
func ComputeHMAC(data string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
