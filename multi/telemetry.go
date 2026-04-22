package multi

// Copyright 2026 Severalnines AB — GPL-2.0 (same as the rest of this repo)

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

const telemetryClientTimeout = 30 * time.Second

// NewTelemetryClient builds the http.Client used by TelemetryProxyRequest
// to forward /proxy/telemetry/* to cc-telemetry. It honours three
// deployment modes for the upstream REST API:
//
//   - Plain HTTP or HTTPS with a publicly-trusted cert: default TLS config
//     (system trust store). No extra config.
//   - HTTPS with a private CA / self-signed cert in on-prem deployments:
//     set cfg.CcTelemetryTLSCA to a PEM bundle that includes the signing
//     CA (or the self-signed cert itself). Added to RootCAs.
//   - Dev / test skip-verify: cfg.CcTelemetryInsecure = true. Flips
//     InsecureSkipVerify on and emits a loud warning at startup so
//     operators don't leave it on in prod.
//
// A misconfigured CA file (unreadable / unparseable) returns an error so
// the proxy fails fast at startup rather than silently fronting a broken
// trust chain.
func NewTelemetryClient(cfg *config.Config) (*http.Client, error) {
	tlsCfg := &tls.Config{}
	switch {
	case cfg != nil && cfg.CcTelemetryInsecure:
		tlsCfg.InsecureSkipVerify = true
		zap.L().Sugar().Warn("[telemetry] TLS verification DISABLED via cc_telemetry_insecure — dev/test only, do not ship to production")
	case cfg != nil && cfg.CcTelemetryTLSCA != "":
		pem, err := os.ReadFile(cfg.CcTelemetryTLSCA)
		if err != nil {
			return nil, fmt.Errorf("read cc_telemetry_tls_ca %q: %w", cfg.CcTelemetryTLSCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse cc_telemetry_tls_ca %q: no PEM certs found", cfg.CcTelemetryTLSCA)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   telemetryClientTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// telemetryHTTPClient lazy-initializes and caches the forwarding client on
// the Proxy so tests that construct &Proxy{cfg: ...} directly still work.
// A nil return with non-nil error means the cert/CA config was invalid;
// TelemetryProxyRequest surfaces that as 502 to the caller.
func (p *Proxy) telemetryHTTPClient() (*http.Client, error) {
	p.telemetryOnce.Do(func() {
		p.telemetryClient, p.telemetryClientErr = NewTelemetryClient(p.cfg)
	})
	return p.telemetryClient, p.telemetryClientErr
}

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

	client, err := p.telemetryHTTPClient()
	if err != nil {
		c.String(http.StatusBadGateway, "cc-telemetry client misconfigured: %v", err)
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

	resp, err := client.Do(req)
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
