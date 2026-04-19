package multi

// Copyright 2026 Severalnines AB — GPL-2.0 (same as the rest of this repo)

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// telemetryClient is a short-timeout http.Client reused across requests.
// Exposed as a package var so tests / tls-overrides can swap it.
var telemetryClient = &http.Client{Timeout: 30 * time.Second}

// TelemetryProxyRequest forwards an authenticated /proxy/telemetry/<path> request
// to cc-telemetry at cfg.CcTelemetryURL, attaches Bearer auth if configured,
// and pipes the response (status + Content-Type + body) back to the caller.
//
// Auth to cmon-proxy itself is enforced by RPCAuthMiddleware at the route group
// level — by the time we get here the operator is already authenticated.
func (p *Proxy) TelemetryProxyRequest(c *gin.Context) {
	cfg := p.cfg
	if cfg == nil || cfg.CcTelemetryURL == "" {
		c.String(http.StatusBadGateway, "cc-telemetry URL is not configured")
		return
	}

	// Upstream path is whatever follows the /proxy/telemetry prefix.
	tail := strings.TrimPrefix(c.Request.URL.Path, "/proxy/telemetry")
	if tail == "" {
		tail = "/"
	}
	target := strings.TrimRight(cfg.CcTelemetryURL, "/") + tail

	var bodyReader io.Reader
	if c.Request.Body != nil {
		buf, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusBadGateway, "read request body: %v", err)
			return
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target, bodyReader)
	if err != nil {
		c.String(http.StatusBadGateway, "build upstream request: %v", err)
		return
	}
	if ct := c.Request.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if ac := c.Request.Header.Get("Accept"); ac != "" {
		req.Header.Set("Accept", ac)
	}
	if cfg.CcTelemetryToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CcTelemetryToken)
	}

	resp, err := telemetryClient.Do(req)
	if err != nil {
		c.String(http.StatusBadGateway, "cc-telemetry unreachable: %v", err)
		return
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		c.Header("Content-Type", ct)
	}
	c.Status(resp.StatusCode)
	_, _ = io.Copy(c.Writer, resp.Body)
}
