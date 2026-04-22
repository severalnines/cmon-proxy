package multi

// Copyright 2026 Severalnines AB — GPL-2.0 (same as the rest of this repo)

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeCertPEM dumps a certificate from an httptest TLS server into a PEM
// file and returns its path. Lets the passthrough exercise the real file-
// read + PEM-parse code paths (not just an in-memory cert pool).
func writeCertPEM(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	require.NotNil(t, srv.Certificate(), "TLS server must expose its self-signed cert")
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream.crt")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return path
}

// TestTelemetryProxyRequest_HTTPSWithTrustedCA — operators deploying
// cc-telemetry behind a private CA / self-signed cert set
// cc_telemetry_tls_ca to the PEM bundle that signs it. The forwarder
// then verifies normally against that bundle, no skip-verify needed.
// This is the production-correct path for on-prem deployments.
func TestTelemetryProxyRequest_HTTPSWithTrustedCA(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	caPath := writeCertPEM(t, upstream)
	p := &Proxy{cfg: &config.Config{
		CcTelemetryURL:   upstream.URL,
		CcTelemetryTLSCA: caPath,
	}}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"status":"ok"`)
}

// TestTelemetryProxyRequest_HTTPSWithInsecureSkip — dev/test flavour.
// Operators flip cc_telemetry_insecure=true to bypass verification
// entirely. The forwarder accepts any cert and logs a loud warning
// (not asserted here; see NewTelemetryClient).
func TestTelemetryProxyRequest_HTTPSWithInsecureSkip(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	p := &Proxy{cfg: &config.Config{
		CcTelemetryURL:      upstream.URL,
		CcTelemetryInsecure: true,
	}}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"status":"ok"`)
}

// TestTelemetryProxyRequest_HTTPSStrictByDefault — without any TLS
// config, an HTTPS upstream using a cert the system trust store
// doesn't know about MUST be rejected. Proves we don't accidentally
// ship a permissive default that hides misconfigurations in prod.
func TestTelemetryProxyRequest_HTTPSStrictByDefault(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`should not be reached`))
	}))
	defer upstream.Close()

	p := &Proxy{cfg: &config.Config{
		CcTelemetryURL: upstream.URL,
		// No CcTelemetryTLSCA, no CcTelemetryInsecure — strict default.
	}}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)

	require.Equal(t, http.StatusBadGateway, w.Code, "strict TLS default must surface a 502 when the upstream cert isn't trusted")
	assert.Contains(t, w.Body.String(), "cc-telemetry unreachable")
	assert.NotContains(t, w.Body.String(), "should not be reached", "handler must never see the upstream body")
}

// TestNewTelemetryClient_BadCAPath — fail-fast on misconfigured CA.
// Returns an error rather than silently falling back to strict default,
// so operators see the problem at startup (where New returns) instead
// of discovering it only when a /proxy/telemetry/* request arrives.
func TestNewTelemetryClient_BadCAPath(t *testing.T) {
	_, err := NewTelemetryClient(&config.Config{
		CcTelemetryTLSCA: "/path/that/definitely/does/not/exist.crt",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cc_telemetry_tls_ca")
}

// TestNewTelemetryClient_UnparseableCA — same fail-fast posture when
// the file exists but isn't a valid PEM bundle.
func TestNewTelemetryClient_UnparseableCA(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "not-a-cert.txt")
	require.NoError(t, os.WriteFile(badPath, []byte("this is not a PEM certificate"), 0600))

	_, err := NewTelemetryClient(&config.Config{CcTelemetryTLSCA: badPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM certs found")
}
