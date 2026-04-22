package multi

// Copyright 2026 Severalnines AB — GPL-2.0 (same as the rest of this repo)

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/rpcserver/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTelemetryPassthrough_RejectsUnauthenticated proves that when the
// /proxy/telemetry/* routes are registered under RPCAuthMiddleware (as
// rpcserver/server.go does), a request without a valid session is rejected
// with 401 before the handler ever runs. Handler-level tests call
// TelemetryProxyRequest directly and would miss a future regression where
// the middleware is accidentally dropped from the route group.
func TestTelemetryPassthrough_RejectsUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Sentinel URL that would fail loudly if the request actually reached
	// the handler — proves the middleware short-circuited.
	sentinelFalse := false
	p := &Proxy{cfg: &config.Config{
		CcTelemetryURL: "http://127.0.0.1:1", // unreachable; handler would 502
		SessionSecure:  &sentinelFalse,
	}}

	eng := gin.New()
	eng.Use(session.Sessions(p.cfg))

	grp := eng.Group("/proxy/telemetry")
	grp.Use(p.RPCAuthMiddleware)
	grp.GET("/status", p.TelemetryProxyRequest)
	grp.POST("/reports", p.TelemetryProxyRequest)

	for _, tc := range []struct {
		name, method, path string
	}{
		{"status without session", http.MethodGet, "/proxy/telemetry/status"},
		{"reports without session", http.MethodPost, "/proxy/telemetry/reports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)

			eng.ServeHTTP(w, req)

			require.Equal(t, http.StatusUnauthorized, w.Code, "middleware must reject before handler runs")
			assert.Contains(t, w.Body.String(), "authentication is required")
			assert.NotContains(t, w.Body.String(), "cc-telemetry unreachable",
				"if the handler ran we would see the upstream error instead")
		})
	}
}
