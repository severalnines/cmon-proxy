package rpcserver

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"path/filepath"
	"testing"

	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/metering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureMeteringKeys_UsesSigningKeyForCurrentKeyID(t *testing.T) {
	configureMeteringKeys(&config.Config{
		MeteringSigningKey: "current-secret",
		MeteringKeyID:      "key-current",
	})

	assert.Equal(t, []byte("current-secret"), verificationKeyForReport("key-current"))
	assert.Equal(t, []byte("current-secret"), verificationKeyForReport(""))
}

func TestConfigureMeteringKeys_SupportsRotatedVerificationKeys(t *testing.T) {
	configureMeteringKeys(&config.Config{
		MeteringSigningKey: "current-secret",
		MeteringKeyID:      "key-current",
		MeteringVerificationKeys: map[string]string{
			"key-old": "old-secret",
		},
	})

	report := &metering.ReportData{ReportVersion: 1}
	sealed, err := metering.SealReport(report, []byte("old-secret"), "key-old")
	require.NoError(t, err)

	hashOK, sigOK := metering.VerifySeal(sealed.CanonicalJSON, sealed.SHA256Hash, sealed.Signature, verificationKeyForReport("key-old"))
	assert.True(t, hashOK)
	assert.True(t, sigOK)
	assert.Equal(t, []byte("old-secret"), verificationKeyForReport("key-old"))
}

func TestConfigureMeteringKeys_MissingVerificationKey(t *testing.T) {
	configureMeteringKeys(&config.Config{
		MeteringSigningKey: "current-secret",
		MeteringKeyID:      "key-current",
	})

	assert.Nil(t, verificationKeyForReport("missing-key"))
}

func TestConfigureMeteringStorage_PersistsRetentionAndSigningKeyID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "metering.db")
	backend, err := metering.NewSQLiteBackend(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })

	configureMeteringKeys(&config.Config{
		MeteringSigningKey: "current-secret",
		MeteringKeyID:      "key-current",
	})

	err = configureMeteringStorage(backend, &config.Config{
		MeteringRetentionMonths: 6,
	})
	require.NoError(t, err)

	ctx := context.Background()
	retentionMonths, err := backend.GetConfig(ctx, metering.ConfigRetentionMonths)
	require.NoError(t, err)
	assert.Equal(t, "6", retentionMonths)

	signingKeyID, err := backend.GetConfig(ctx, metering.ConfigSigningKeyID)
	require.NoError(t, err)
	assert.Equal(t, "key-current", signingKeyID)
}

func TestGenerateCSVZip_UsesBillingTableRows(t *testing.T) {
	zipBuf, err := generateCSVZip(&metering.ReportData{
		BillingTableRows: []metering.BillingTableRow{
			{
				RowType:            "vendor",
				DeploymentType:     "galera",
				Vendor:             "percona",
				MaxConcurrentNodes: 3,
				MaxVCPU:            24,
				MaxRAMGB:           48,
				MaxVolumeGB:        600,
			},
			{
				RowType:            "grand_total",
				Vendor:             "Grand Total",
				MaxConcurrentNodes: 3,
				MaxVCPU:            24,
				MaxRAMGB:           48,
				MaxVolumeGB:        600,
			},
		},
		NodeDetails: []metering.NodeDetail{
			{
				NodeID:       "ctrl-1:10.0.1.1",
				ControllerID: "ctrl-1",
				ClusterID:    1,
				ClusterName:  "prod",
				ClusterType:  "galera",
				DBVendor:     "percona",
				NodeRole:     "database",
				ActiveHours:  24,
			},
		},
	})
	require.NoError(t, err)

	reader, err := zip.NewReader(bytes.NewReader(zipBuf), int64(len(zipBuf)))
	require.NoError(t, err)
	require.Len(t, reader.File, 2)

	summaryRows := readCSVFromZip(t, reader, "summary.csv")
	require.Len(t, summaryRows, 3)
	assert.Equal(t, []string{"row_type", "deployment_type", "vendor", "max_concurrent_nodes", "max_vcpu", "max_ram_gb", "max_volume_gb"}, summaryRows[0])
	assert.Equal(t, []string{"vendor", "galera", "percona", "3", "24", "48", "600"}, summaryRows[1])
	assert.Equal(t, []string{"grand_total", "", "Grand Total", "3", "24", "48", "600"}, summaryRows[2])
}

func readCSVFromZip(t *testing.T, reader *zip.Reader, name string) [][]string {
	t.Helper()

	for _, file := range reader.File {
		if file.Name != name {
			continue
		}

		rc, err := file.Open()
		require.NoError(t, err)
		defer rc.Close()

		body, err := io.ReadAll(rc)
		require.NoError(t, err)

		rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
		require.NoError(t, err)
		return rows
	}

	t.Fatalf("zip entry %s not found", name)
	return nil
}
