package metering

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalJSON_Deterministic(t *testing.T) {
	report := &ReportData{
		ReportVersion: 1,
		PeriodStart:   "2026-04-01T00:00:00Z",
		PeriodEnd:     "2026-04-30T23:59:59Z",
		GeneratedAt:   "2026-05-01T00:00:00Z",
		Summary: ReportSummary{
			TotalBillableNodes: 2,
			GrandTotalMaxVCPU:  8,
		},
		ByTypeAndVendor: []TypeVendorSummary{
			{ClusterType: "galera", DBVendor: "percona", MaxConcurrentNodes: 2},
		},
		NodeDetails: []NodeDetail{
			{NodeID: "ctrl-1:10.0.1.1", ActiveHours: 720},
		},
	}

	json1, err := CanonicalJSON(report)
	require.NoError(t, err)

	json2, err := CanonicalJSON(report)
	require.NoError(t, err)

	assert.Equal(t, json1, json2)
	assert.NotEmpty(t, json1)

	// Should not contain pretty-printed whitespace.
	assert.NotContains(t, json1, "\n")
}

func TestComputeSHA256(t *testing.T) {
	hash := ComputeSHA256("hello world")
	assert.Equal(t, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash)

	// Different input → different hash.
	hash2 := ComputeSHA256("hello world!")
	assert.NotEqual(t, hash, hash2)
}

func TestComputeHMAC(t *testing.T) {
	key := []byte("test-signing-key")

	sig1 := ComputeHMAC("some data", key)
	assert.NotEmpty(t, sig1)

	// Same input + key → same signature.
	sig2 := ComputeHMAC("some data", key)
	assert.Equal(t, sig1, sig2)

	// Different data → different signature.
	sig3 := ComputeHMAC("other data", key)
	assert.NotEqual(t, sig1, sig3)

	// Different key → different signature.
	sig4 := ComputeHMAC("some data", []byte("different-key"))
	assert.NotEqual(t, sig1, sig4)
}

func TestSealReport(t *testing.T) {
	report := &ReportData{
		ReportVersion: 1,
		PeriodStart:   "2026-04-01T00:00:00Z",
		PeriodEnd:     "2026-04-30T23:59:59Z",
		GeneratedAt:   "2026-05-01T00:00:00Z",
		Summary:       ReportSummary{TotalBillableNodes: 5},
	}

	key := []byte("my-secret-key")
	result, err := SealReport(report, key, "key-2026-01")
	require.NoError(t, err)

	assert.NotEmpty(t, result.CanonicalJSON)
	assert.NotEmpty(t, result.SHA256Hash)
	assert.NotEmpty(t, result.Signature)
	assert.Equal(t, "key-2026-01", result.SigningKeyID)

	// Hash should match direct computation.
	assert.Equal(t, ComputeSHA256(result.CanonicalJSON), result.SHA256Hash)

	// Signature should match direct HMAC computation.
	assert.Equal(t, ComputeHMAC(result.SHA256Hash, key), result.Signature)
}

func TestSealReport_NoKey(t *testing.T) {
	report := &ReportData{
		ReportVersion: 1,
		PeriodStart:   "2026-04-01T00:00:00Z",
		PeriodEnd:     "2026-04-30T23:59:59Z",
		GeneratedAt:   "2026-05-01T00:00:00Z",
	}

	result, err := SealReport(report, nil, "")
	require.NoError(t, err)

	assert.NotEmpty(t, result.SHA256Hash)
	assert.Empty(t, result.Signature) // No key → no signature.
}

func TestVerifySeal_Valid(t *testing.T) {
	report := &ReportData{
		ReportVersion: 1,
		PeriodStart:   "2026-04-01T00:00:00Z",
		PeriodEnd:     "2026-04-30T23:59:59Z",
		GeneratedAt:   "2026-05-01T00:00:00Z",
		Summary:       ReportSummary{TotalBillableNodes: 10},
	}

	key := []byte("signing-key")
	sealed, err := SealReport(report, key, "key-1")
	require.NoError(t, err)

	hashOK, sigOK := VerifySeal(sealed.CanonicalJSON, sealed.SHA256Hash, sealed.Signature, key)
	assert.True(t, hashOK)
	assert.True(t, sigOK)
}

func TestVerifySeal_TamperedData(t *testing.T) {
	report := &ReportData{
		ReportVersion: 1,
		PeriodStart:   "2026-04-01T00:00:00Z",
		PeriodEnd:     "2026-04-30T23:59:59Z",
		GeneratedAt:   "2026-05-01T00:00:00Z",
		Summary:       ReportSummary{TotalBillableNodes: 10},
	}

	key := []byte("signing-key")
	sealed, err := SealReport(report, key, "key-1")
	require.NoError(t, err)

	// Tamper with the data.
	tampered := sealed.CanonicalJSON + "x"
	hashOK, sigOK := VerifySeal(tampered, sealed.SHA256Hash, sealed.Signature, key)
	assert.False(t, hashOK)
	assert.False(t, sigOK)
}

func TestVerifySeal_WrongKey(t *testing.T) {
	report := &ReportData{
		ReportVersion: 1,
		PeriodStart:   "2026-04-01T00:00:00Z",
		PeriodEnd:     "2026-04-30T23:59:59Z",
		GeneratedAt:   "2026-05-01T00:00:00Z",
	}

	key := []byte("correct-key")
	sealed, err := SealReport(report, key, "key-1")
	require.NoError(t, err)

	wrongKey := []byte("wrong-key")
	hashOK, sigOK := VerifySeal(sealed.CanonicalJSON, sealed.SHA256Hash, sealed.Signature, wrongKey)
	assert.True(t, hashOK)   // Hash doesn't depend on key.
	assert.False(t, sigOK)   // Signature verification fails.
}

func TestVerifySeal_NoSignature(t *testing.T) {
	data := `{"report_version":1}`
	hash := ComputeSHA256(data)

	hashOK, sigOK := VerifySeal(data, hash, "", nil)
	assert.True(t, hashOK)
	assert.True(t, sigOK) // No key, no signature expected → trivially valid.
}
