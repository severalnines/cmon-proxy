package multi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTelemetryProxyRequest_ForwardsGET(t *testing.T) {
	var gotAuth, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"total_snapshots": 42})
	}))
	defer upstream.Close()

	p := &Proxy{cfg: &config.Config{
		OtelMeteringEnabled: true,
		CcTelemetryURL:   upstream.URL,
		CcTelemetryToken: "s3cret",
	}}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/status", gotPath, "path after /proxy/telemetry must be forwarded verbatim")
	assert.Equal(t, "Bearer s3cret", gotAuth)
	assert.Contains(t, w.Body.String(), `"total_snapshots":42`)
}

func TestTelemetryProxyRequest_ForwardsPOSTBody(t *testing.T) {
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"report_id":7}`))
	}))
	defer upstream.Close()

	p := &Proxy{cfg: &config.Config{OtelMeteringEnabled: true, CcTelemetryURL: upstream.URL}}
	body := strings.NewReader(`{"operation":"listReports"}`)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/proxy/telemetry/reports", body)
	ctx.Request.Header.Set("Content-Type", "application/json")

	p.TelemetryProxyRequest(ctx)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `{"operation":"listReports"}`, string(gotBody))
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestTelemetryProxyRequest_NoTokenSkipsAuthHeader(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := &Proxy{cfg: &config.Config{OtelMeteringEnabled: true, CcTelemetryURL: upstream.URL}}
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)
	assert.Empty(t, gotAuth, "no token configured → no Authorization header")
}

func TestTelemetryProxyRequest_Upstream5xxSurfacesAs502(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer upstream.Close()

	p := &Proxy{cfg: &config.Config{OtelMeteringEnabled: true, CcTelemetryURL: upstream.URL}}
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "upstream status must be mirrored verbatim")
	assert.Contains(t, w.Body.String(), "boom")
}

func TestTelemetryProxyRequest_UpstreamDownReturns502(t *testing.T) {
	p := &Proxy{cfg: &config.Config{OtelMeteringEnabled: true, CcTelemetryURL: "http://127.0.0.1:1"}} // port-1 is unreachable
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestTelemetryProxyRequest_FeatureDisabledReturns404(t *testing.T) {
	p := &Proxy{cfg: &config.Config{
		OtelMeteringEnabled: false,
		CcTelemetryURL:      "http://127.0.0.1:1",
	}}
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/proxy/telemetry/status", nil)

	p.TelemetryProxyRequest(ctx)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "billing is disabled")
}
