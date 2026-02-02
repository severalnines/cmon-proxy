package rpcserver

// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/secure"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/severalnines/cmon-proxy/config"
	k8s "github.com/severalnines/cmon-proxy/k8s"
	"github.com/severalnines/cmon-proxy/multi"
	"github.com/severalnines/cmon-proxy/multi/router"
	"github.com/severalnines/cmon-proxy/opts"
	"github.com/severalnines/cmon-proxy/poolhelpers"
	"github.com/severalnines/cmon-proxy/rpcserver/session"
	"go.uber.org/zap"
)

var (
	httpServer      *http.Server
	httpServerPlain *http.Server
	proxy           *multi.Proxy
)

type GinWriteInterceptor struct {
	gin.ResponseWriter
	responseBody *bytes.Buffer
}

func (gwi *GinWriteInterceptor) WriteString(str string) (int, error) {
	gwi.responseBody.WriteString(str)
	return gwi.ResponseWriter.WriteString(str)
}

func (gwi *GinWriteInterceptor) Write(bs []byte) (int, error) {
	gwi.responseBody.Write(bs)
	return gwi.ResponseWriter.Write(bs)
}

func WebRpcDebugMiddleware(c *gin.Context) {
	logger := zap.L().Sugar()
	start := time.Now()

	// we need to replace the writer to be able to capture the response body
	bodyWriter := &GinWriteInterceptor{
		ResponseWriter: c.Writer,
		responseBody:   bytes.NewBufferString(""),
	}
	c.Writer = bodyWriter

	if false {
		// log the incoming request
		body, _ := io.ReadAll(c.Copy().Request.Body)
		logger.Debugf("Web request [%s] %s %s:\n%s",
			c.ClientIP(), c.Request.Method, c.Request.RequestURI, string(body))
	} else {
		logger.Debugf("Web request [%s] %s %s",
			c.ClientIP(), c.Request.Method, c.Request.RequestURI)
	}

	// call handlers
	c.Next()

	// check elapsed time
	elapsed := time.Since(start)

	// and then log the reply too
	logger.Debugf("Web reply   [%s] (elapsed: %dms) status %d:\n%s",
		c.ClientIP(), int64(elapsed/time.Millisecond), c.Copy().Writer.Status(), bodyWriter.responseBody.String())
}

func serveStaticOrIndex(c *gin.Context, path string, cfg *config.Config) {
	filePath := filepath.Join(path, c.Request.URL.Path)
	filePath, err := filepath.EvalSymlinks(filePath)
	if err != nil || !strings.HasPrefix(filePath, path) {
		filePath = filepath.Join(path, "index.html")
	}
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) || info.IsDir() {
		filePath = filepath.Join(path, "index.html")
		info, err = os.Stat(filePath)
		if os.IsNotExist(err) || info.IsDir() {
			c.Next()
			return
		}
	}

	// Check if this file needs nonce replacement based on configuration
	needsNonceReplacement := false
	fileName := filepath.Base(filePath)
	for _, configuredFile := range cfg.WebServer.Frontend.NonceReplacementFiles {
		if fileName == configuredFile {
			needsNonceReplacement = true
			break
		}
	}

	if needsNonceReplacement {
		// Read the HTML file and replace __NONCE__ with actual nonce
		content, err := os.ReadFile(filePath)
		if err != nil {
			c.Status(http.StatusInternalServerError)
			c.Abort()
			return
		}

		// Generate a fresh nonce and set CSP header here for HTML
		nonce := generateNonce()
		if cfg.WebServer.Security.ContentSecurityPolicy != "" {
			csp := strings.ReplaceAll(cfg.WebServer.Security.ContentSecurityPolicy, "{{nonce}}", nonce)
			if *cfg.WebServer.Security.ContentSecurityPolicyReportOnly {
				// Remove invalid directives in report-only mode and normalize
				csp = sanitizeCSPForReportOnly(csp)
				c.Header("Content-Security-Policy-Report-Only", csp)
			} else {
				c.Header("Content-Security-Policy", csp)
			}
		}
		// Store nonce in context for potential downstream usage
		c.Set("csp-nonce", nonce)

		// Replace __NONCE__ placeholders with actual nonce
		contentStr := strings.ReplaceAll(string(content), "__NONCE__", nonce)
		content = []byte(contentStr)

		// Set appropriate headers for HTML content
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate") // Don't cache HTML with nonces
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Data(http.StatusOK, "text/html; charset=utf-8", content)
		c.Abort()
		return
	}

	// For non-HTML files, serve normally with caching
	c.Header("Cache-Control", "public, max-age=31536000")
	lastModified := info.ModTime().UTC().Format(http.TimeFormat)
	c.Header("Last-Modified", lastModified)
	etag := generateETag(info)
	c.Header("ETag", etag)

	c.File(filePath)
	c.Abort()
}

func generateETag(info os.FileInfo) string {
	hash := md5.New()
	_, _ = fmt.Fprintf(hash, "%s-%d-%d", info.Name(), info.Size(), info.ModTime().Unix())
	return fmt.Sprintf(`"%x"`, hash.Sum(nil))
}

// generateNonce creates a cryptographically secure random nonce for CSP
func generateNonce() string {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		// fallback to a timestamp-based nonce if random generation fails
		return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return base64.URLEncoding.EncodeToString(nonceBytes)
}

// sanitizeCSPForReportOnly removes directives that are invalid in report-only mode
// and normalizes the directive list formatting.
func sanitizeCSPForReportOnly(csp string) string {
	// Remove the standalone directive token 'upgrade-insecure-requests'
	// by splitting into directives and filtering.
	directives := strings.Split(csp, ";")
	cleaned := make([]string, 0, len(directives))
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}
		if strings.EqualFold(directive, "upgrade-insecure-requests") {
			continue
		}
		cleaned = append(cleaned, directive)
	}
	return strings.Join(cleaned, "; ")
}

func getFrontendPath(cfg *config.Config) (string, error) {
	cleanPath, err := filepath.EvalSymlinks(cfg.FrontendPath)
	if err != nil {
		return "", err
	}
	return cleanPath, nil
}

func serveFrontend(s *gin.Engine, cfg *config.Config) error {
	cleanPath, err := getFrontendPath(cfg)
	s.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/proxy/") ||
			strings.HasPrefix(c.Request.URL.Path, "/single/") ||
			strings.HasPrefix(c.Request.URL.Path, "/v2/") ||
			strings.HasPrefix(c.Request.URL.Path, "/cmon/") {
			c.Next()
		} else {
			if err != nil {
				c.String(http.StatusNotFound, "Not Found")
				c.Abort()
				return
			}

			// Handling the special case for config.js
			if c.Request.URL.Path == "/ccmgr.js" {
				registration := false
				if len(cfg.Users) < 1 {
					registration = true
				}
				// Generate another object to filter some fields from config
				configToReturn := gin.H{
					"SINGLE_CONTROLLER":         cfg.SingleController,
					"REGISTRATION":              registration,
					"MCC_API_URL":               "/proxy",
					"SINGLE_CONTROLLER_API_URL": "/single/v2",
					"MULTI_CONTROLLER_API_URL":  "/v2",
					"KUBERNETES_ENABLED":        cfg.KubernetesEnabled,
					"POOL_VISIBLE":              cfg.PoolVisible,
					"INSTANCES":                 cfg.Instances,
				}

				jsonBytes, err := json.Marshal(configToReturn)
				if err != nil {
					c.String(http.StatusNotFound, "Failed to generate environment variables")
					return
				}

				// Convert JSON bytes to string
				jsonStr := string(jsonBytes)

				// Create the JavaScript response
				jsContent := fmt.Sprintf("window.CCMGR = %s;", jsonStr)
				c.Header("Content-Type", "application/javascript")
				c.String(http.StatusOK, jsContent)
				c.Abort()
				return
			}

			if c.Request.URL.Path == "/cc-license" {
				targetUrl, err := url.Parse(cfg.LicenseProxyURL)
				if err != nil {
					c.String(http.StatusBadGateway, "Invalid license proxy URL: %v", err)
					c.Abort()
					return
				}
				// Copy query params from incoming request
				q := c.Request.URL.Query()
				targetUrl.RawQuery = q.Encode()

				// Create a new request to preserve headers
				req, err := http.NewRequest("GET", targetUrl.String(), nil)
				if err != nil {
					c.String(http.StatusBadGateway, "Failed to create request: %v", err)
					c.Abort()
					return
				}

				// Forward the original client's IP address if it is a public address
				if clientIP, ok := publicClientIP(c); ok {
					req.Header.Set("X-Forwarded-For", clientIP)
					req.Header.Set("X-Real-IP", clientIP)
				}

				// Forward other relevant headers that might be needed for geo-location
				if userAgent := c.GetHeader("User-Agent"); userAgent != "" {
					req.Header.Set("User-Agent", userAgent)
				}
				if acceptLanguage := c.GetHeader("Accept-Language"); acceptLanguage != "" {
					req.Header.Set("Accept-Language", acceptLanguage)
				}
				if accept := c.GetHeader("Accept"); accept != "" {
					req.Header.Set("Accept", accept)
				}

				// Create HTTP client and make the request
				client := &http.Client{
					Timeout: time.Second * 30,
				}
				resp, err := client.Do(req)
				if err != nil {
					c.String(http.StatusBadGateway, "Failed to fetch license: %v", err)
					c.Abort()
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
				c.Abort()
				return
			}

			if !strings.HasPrefix(cleanPath, cfg.WebAppRoot) {
				c.String(http.StatusForbidden, "Access Denied")
				c.Abort()
				return
			}
			serveStaticOrIndex(c, cleanPath, cfg)
		}
	})

	return nil
}

func publicClientIP(c *gin.Context) (string, bool) {
	ip := c.ClientIP()
	if ip == "" {
		return "", false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	// Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:192.0.2.1) so private RFC1918
	// ranges are detected correctly.
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return "", false
	}
	return addr.String(), true
}

func forwardToCmon(ctx *gin.Context) {
	// Proxy requests to cmon (must have xid or controller_id for routing)
	// Note: controller_id in requests is for the cmon instance itself, not for proxy routing.
	// The proxy uses xid for routing. If controller_id is provided as a number (e.g., in pool controller requests),
	// we extract xid for routing and pass controller_id through to the actual cmon request.
	method := ctx.Request.Method
	jsonData, err := io.ReadAll(ctx.Request.Body)

	var requestMap map[string]interface{}
	var controllerId cmonapi.WithControllerID
	var routingID string

	if err == nil && len(jsonData) > 0 {
		// First, parse as a map to handle controller_id as either number or string
		err = json.Unmarshal(jsonData, &requestMap)
		if err == nil {
			// Extract xid first (preferred for routing)
			if xidVal, ok := requestMap["xid"].(string); ok && len(xidVal) > 4 {
				controllerId.Xid = xidVal
				routingID = xidVal
			}

			// Handle controller_id as either number or string
			// Note: controller_id is for the cmon instance, not for proxy routing
			if controllerIDVal, ok := requestMap["controller_id"]; ok {
				switch v := controllerIDVal.(type) {
				case string:
					controllerId.ControllerID = v
					// Only use controller_id for routing if xid is not available
					if routingID == "" && len(v) > 0 {
						routingID = v
					}
				case float64: // JSON numbers unmarshal as float64
					// Convert to string without decimal places if it's a whole number
					if v == float64(int64(v)) {
						controllerId.ControllerID = strconv.FormatInt(int64(v), 10)
					} else {
						controllerId.ControllerID = strconv.FormatFloat(v, 'f', -1, 64)
					}
					// Convert controller_id to string in the request map for proper forwarding
					requestMap["controller_id"] = controllerId.ControllerID
					// Re-marshal the request with controller_id as string
					jsonData, err = json.Marshal(requestMap)
				case int:
					controllerId.ControllerID = strconv.Itoa(v)
					requestMap["controller_id"] = controllerId.ControllerID
					jsonData, err = json.Marshal(requestMap)
				case int64:
					controllerId.ControllerID = strconv.FormatInt(v, 10)
					requestMap["controller_id"] = controllerId.ControllerID
					jsonData, err = json.Marshal(requestMap)
				}
			}
		}
	}

	if len(jsonData) < 2 && len(ctx.Request.URL.Query()) > 0 {
		// lets try to construct a POST request from URL query parameters
		// (this is for testing / simplify)
		jsonMap := make(map[string]interface{})
		for param, args := range ctx.Request.URL.Query() {
			if len(args) < 1 {
				continue
			}
			if _, found := jsonMap[param]; !found {
				jsonMap[param] = args[0]
			}
		}
		// okay we converted all URL query args into a JSON map
		jsonData, err = json.Marshal(jsonMap)
		method = "POST"
		// Re-parse after constructing from query params
		if err == nil {
			err = json.Unmarshal(jsonData, &requestMap)
			if err == nil {
				if xidVal, ok := requestMap["xid"].(string); ok && len(xidVal) > 4 {
					controllerId.Xid = xidVal
					routingID = xidVal
				}
				if controllerIDVal, ok := requestMap["controller_id"]; ok {
					switch v := controllerIDVal.(type) {
					case string:
						controllerId.ControllerID = v
						// Only use controller_id for routing if xid is not available
						if routingID == "" && len(v) > 0 {
							routingID = v
						}
					case float64:
						// Convert to string without decimal places if it's a whole number
						if v == float64(int64(v)) {
							controllerId.ControllerID = strconv.FormatInt(int64(v), 10)
						} else {
							controllerId.ControllerID = strconv.FormatFloat(v, 'f', -1, 64)
						}
						requestMap["controller_id"] = controllerId.ControllerID
						jsonData, err = json.Marshal(requestMap)
					case int:
						controllerId.ControllerID = strconv.Itoa(v)
						requestMap["controller_id"] = controllerId.ControllerID
						jsonData, err = json.Marshal(requestMap)
					case int64:
						controllerId.ControllerID = strconv.FormatInt(v, 10)
						requestMap["controller_id"] = controllerId.ControllerID
						jsonData, err = json.Marshal(requestMap)
					}
				}
			}
		}
	}

	if err != nil {
		var resp cmonapi.WithResponseData
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "couldn't read request body: " + err.Error()
		ctx.JSON(http.StatusBadRequest, resp)
		return
	}

	// Use xid for routing if available, otherwise fall back to controller_id
	if routingID == "" {
		if len(controllerId.Xid) > 4 {
			routingID = controllerId.Xid
		} else if len(controllerId.ControllerID) > 0 {
			routingID = controllerId.ControllerID
		}
	}

	if routingID == "" {
		var resp cmonapi.WithResponseData
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "missing xid or controller_id from request"
		ctx.JSON(http.StatusBadRequest, resp)
		return
	}

	controllers := proxy.GetCachedPoolControllers(ctx, routingID)
	activeTargets := poolhelpers.FilterActivePoolControllers(controllers)

	if poolhelpers.TrySmartRouteAcrossPool(ctx, routingID, jsonData, activeTargets, nil, nil, func(ctx *gin.Context) *router.Router { return proxy.Router(ctx) }) {
		return
	}

	proxy.RPCProxyRequest(ctx, routingID, method, jsonData)
}

func multiCmon(ctx *gin.Context) {
	// Proxy requests to all cmons
	var xids cmonapi.WithMultiXIds
	method := ctx.Request.Method
	jsonData, err := io.ReadAll(ctx.Request.Body)

	if err == nil {
		err = json.Unmarshal(jsonData, &xids)
	}

	if len(jsonData) < 2 && len(ctx.Request.URL.Query()) > 0 {
		// lets try to construct a POST request from URL query parameters
		// (this is for testing / simplify)
		jsonMap := make(map[string]interface{})
		for param, args := range ctx.Request.URL.Query() {
			if len(args) < 1 {
				continue
			}
			if param == "xids" {
				xids.Xids = strings.Split(args[0], ",")
			}
			if _, found := jsonMap[param]; !found {
				jsonMap[param] = args[0]
			}
		}
		// okay we converted all URL query args into a JSON map
		jsonData, err = json.Marshal(jsonMap)
		method = "POST"
	}

	if err != nil {
		var resp cmonapi.WithResponseData
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "couldn't read request body: " + err.Error()
		ctx.JSON(http.StatusBadRequest, resp)
		return
	}

	proxy.RPCProxyMany(ctx, xids.Xids, method, jsonData)
}

func applyWebServerConfig(r *gin.Engine, cfg config.WebServer) {

	// Trust chain/IP handling (important if behind LB)
	if cfg.TrustedProxies != nil {
		if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
			log.Fatalf("trusted proxies: %v", err)
		}
	}
	if cfg.TrustedPlatform != "" {
		// r.SetTrustedPlatform(cfg.Server.TrustedPlatform)
		r.TrustedPlatform = cfg.TrustedPlatform
	}

	// Security headers (excluding CSP which needs per-request nonce)
	sec := secure.New(secure.Config{
		FrameDeny:            unPtr(cfg.Security.FrameDeny),
		STSSeconds:           cfg.Security.STSSeconds,
		STSIncludeSubdomains: unPtr(cfg.Security.STSIncludeSubdomains),
		STSPreload:           unPtr(cfg.Security.STSPreload),
		ContentTypeNosniff:   unPtr(cfg.Security.ContentTypeNosniff),
		BrowserXssFilter:     unPtr(cfg.Security.BrowserXssFilter),
		ReferrerPolicy:       cfg.Security.ReferrerPolicy,
	})
	r.Use(sec)

	// CORS - only apply if configured
	if len(cfg.CORS.AllowOrigins) > 0 || len(cfg.CORS.AllowMethods) > 0 {
		r.Use(cors.New(cors.Config{
			AllowOrigins:     cfg.CORS.AllowOrigins,
			AllowMethods:     cfg.CORS.AllowMethods,
			AllowHeaders:     cfg.CORS.AllowHeaders,
			ExposeHeaders:    cfg.CORS.ExposeHeaders,
			AllowCredentials: unPtr(cfg.CORS.AllowCredentials),
			MaxAge:           time.Duration(cfg.CORS.MaxAgeSeconds) * time.Second,
		}))
	}

	// Custom security headers middleware; CSP handled where HTML is served
	r.Use(func(c *gin.Context) {
		// Handle ForceSTSHeader - force STS header with configured values
		if *cfg.Security.ForceSTSHeader {
			stsValue := fmt.Sprintf("max-age=%d", cfg.Security.STSSeconds)
			if *cfg.Security.STSIncludeSubdomains {
				stsValue += "; includeSubDomains"
			}
			if *cfg.Security.STSPreload {
				stsValue += "; preload"
			}
			c.Header("Strict-Transport-Security", stsValue)
		}

		// CSP is attached only when serving HTML in serveStaticOrIndex

		if cfg.Security.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", cfg.Security.PermissionsPolicy)
		}
	})

	// Gzip (responses)
	r.Use(gzip.Gzip(cfg.Gzip.Level))
}

// fetchMissingControllerIDs checks all instances for missing controller_id and fetches them
func fetchMissingPoolIds(proxy *multi.Proxy) {
	log := zap.L()

	cfg := proxy.Router(nil).Config
	if cfg == nil {
		log.Warn("Config is nil, cannot fetch missing pool IDs")
		return
	}

	changed := false
	for _, instance := range cfg.Instances {
		if instance != nil && instance.PoolId == "" {
			log.Info("Found instance with missing pool_id, attempting to fetch",
				zap.String("url", instance.Url),
				zap.String("xid", instance.Xid))

			poolId, err := proxy.FetchPoolIdFromInfo(instance)
			if err != nil {
				log.Warn("Failed to fetch pool_id from /info endpoint",
					zap.String("url", instance.Url),
					zap.Error(err))
			} else {
				log.Info("Successfully fetched pool_id",
					zap.String("url", instance.Url),
					zap.String("pool_id", poolId))
				instance.ControllerId = poolId
				instance.PoolId = poolId
				changed = true
			}
		}
	}

	// Save the config if any controller_ids were fetched
	if changed {
		if err := cfg.Save(); err != nil {
			log.Error("Failed to save config after fetching pool_ids", zap.Error(err))
		} else {
			log.Info("Successfully saved config with updated pool_ids")
		}
	}
}

// Start is starting the service
func Start(cfg *config.Config) {
	var err error
	var certManager *autocert.Manager

	// get logger
	log := zap.L()

	if httpServer != nil {
		log.Sugar().Fatalln("rpcserver is already running")
		return
	}

	// Setup Let's Encrypt if enabled
	if cfg.AcmeEnabled {
		if len(cfg.AcmeDomains) == 0 {
			log.Sugar().Fatal("Let's Encrypt is enabled, but no domains are configured (acme_domains)")
		}
		if !cfg.AcmeAcceptTOS {
			log.Sugar().Fatal("Let's Encrypt is enabled, but 'acme_accept_tos' is not set to true in the configuration. You must accept the Let's Encrypt Terms of Service.")
		}
		if cfg.HTTPPort != 80 {
			log.Sugar().Warn("Let's Encrypt is enabled, but HTTP port is not 80. ACME http-01 challenge might fail.")
		}

		var renewBefore time.Duration
		if cfg.AcmeRenewBefore != "" {
			var err error
			renewBefore, err = time.ParseDuration(cfg.AcmeRenewBefore)
			if err != nil {
				log.Sugar().Fatalf("Invalid acme_renew_before duration: %v", err)
			}
		}

		certManager = &autocert.Manager{
			Cache:       autocert.DirCache(cfg.AcmeCacheDir),
			Email:       cfg.AcmeEmail,
			RenewBefore: renewBefore,
			Prompt:      autocert.AcceptTOS,
		}
		if cfg.AcmeDirectoryURL != "" {
			certManager.Client = &acme.Client{DirectoryURL: cfg.AcmeDirectoryURL}
		}

		if cfg.AcmeHostPolicyStrict {
			certManager.HostPolicy = autocert.HostWhitelist(cfg.AcmeDomains...)
		}
	}

	// HTTP server for redirection and Let's Encrypt challenges
	go func() {
		httpLog := zap.L().Sugar().Named("http-server")

		redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}

			target := "https://" + host
			if cfg.Port != 443 {
				target += ":" + strconv.Itoa(cfg.Port)
			}
			target += r.URL.RequestURI()

			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})

		var httpHandler http.Handler = redirectHandler
		if certManager != nil {
			httpHandler = certManager.HTTPHandler(httpHandler)
		}

		httpServerPlain = &http.Server{
			Addr:    ":" + strconv.Itoa(cfg.HTTPPort),
			Handler: httpHandler,
		}

		httpLog.Infof("Starting HTTP Server on port %d for redirection and ACME challenges", cfg.HTTPPort)
		if err := httpServerPlain.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			httpLog.Fatalf("HTTP server failure on port %d: %s", cfg.HTTPPort, err.Error())
		}
	}()

	// Create gin engine and apply web server configuration
	s := gin.New()

	// Apply web server configuration (CORS, security headers, gzip, etc.)
	applyWebServerConfig(s, cfg.WebServer)

	// Add application-specific middleware
	s.Use(ginzap.RecoveryWithZap(log, true))
	s.NoMethod(func(c *gin.Context) { c.JSON(http.StatusMethodNotAllowed, gin.H{"err": "method not allowed"}) })

	s.OPTIONS("*any", func(c *gin.Context) {
		c.Header("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE,HEAD")
		c.Status(http.StatusOK)
	})

	s.Use(session.Sessions(cfg))

	if opts.Opts.DebugWebRpc {
		s.Use(WebRpcDebugMiddleware)
	}

	zap.L().Info("Starting RPC service")

	proxy, err = multi.New(cfg)
	if err != nil {
		log.Sugar().Fatalf("initialization problem: %s", err.Error())
	}

	// Fetch missing controller_ids during startup
	fetchMissingPoolIds(proxy)

	multi.StartSessionCleanupScheduler(proxy)

	// to serve the static files
	err = serveFrontend(s, cfg)
	if err != nil {
		log.Sugar().Fatalln("Error serving frontend: ", err)
		return
	}

	/**
	this intends to be a new way of proxying requests to CMON,
	instead of having param in GET or POST request we take xid from URL
	@todo think about calling "forwardToCmon" handler here as well
	*/
	ssh := s.Group("/cmon/:xid/v2/")
	{
		ssh.Use(proxy.RPCAuthMiddleware)
		// @todo if we want to call "forwardToCmon" in this group need to figure out the way to avoid routes conflict
		ssh.GET("/cmon-ssh/*any", func(c *gin.Context) {
			// could not find better to check if it is a websocket request or not
			if c.GetHeader("Upgrade") == "websocket" {
				proxy.CmonShhWsProxyRequest(c)
			} else {
				proxy.CmonShhHttpProxyRequest(c)
			}
		})

	}

	k8sClient, err := k8s.NewK8sProxyClient(cfg, func(ctx *gin.Context) *router.Router { return proxy.Router(ctx) })
	if err != nil {
		log.Sugar().Fatalf("initialization problem: %s", err.Error())
	}

	single := s.Group("/single")
	{
		// Define /v2 group - use a single handler for all routes to avoid route conflicts
		singleV2 := single.Group("/v2")
		singleV2.POST("/*any", func(c *gin.Context) {
			// Check if this is the /auth endpoint
			if c.Param("any") == "/auth" || strings.HasSuffix(c.Request.URL.Path, "/v2/auth") {
				// Auth endpoint doesn't need middleware (it handles its own auth)
				proxy.PRCProxySingleControllerWithPoolSupport(c)
				return
			}
			// Apply auth middleware for other routes
			proxy.RPCAuthMiddleware(c)
			if c.IsAborted() {
				return
			}
			proxy.PRCProxySingleControllerWithPoolSupport(c)
		})

		k8s := single.Group("/k8s")
		{
			k8sProxyHandler := func(c *gin.Context) {
				proxy.RPCAuthMiddleware(c)
				path := c.Param("path")
				k8sClient.ProxyRequest(c, path)
			}
			k8s.GET("/*path", k8sProxyHandler)
			k8s.POST("/*path", k8sProxyHandler)
			k8s.PUT("/*path", k8sProxyHandler)
			k8s.DELETE("/*path", k8sProxyHandler)
		}

		single.GET("/cmon-ssh/*any", func(c *gin.Context) {
			// could not find better to check if it is a websocket request or not
			if strings.EqualFold(c.GetHeader("Upgrade"), "websocket") {
				proxy.PRCProxySingleControllerWebSocket(c)
			} else {
				proxy.PRCProxySingleControllerHttp(c)
			}
		})

	}

	// Proxy any /v2 requests to the specified (by controller_id) cmon
	v2 := s.Group("/v2")
	{
		v2.Use(proxy.RPCAuthMiddleware)
		v2.POST("/*any", forwardToCmon)
		v2.GET("/*any", forwardToCmon)
	}

	v2multi := s.Group("/v2multi")
	{
		v2multi.Use(proxy.RPCAuthMiddleware)
		v2multi.POST("/*any", multiCmon)
		v2multi.GET("/*any", multiCmon)
	}

	// aggregating APIs for WEB UI v0
	p := s.Group("/proxy")
	{

		configGroup := p.Group("/config")
		configGroup.Use(proxy.RPCAuthMiddleware)
		{
			configGroup.GET("", proxy.RPCConfigHandler)
			configGroup.POST("", proxy.RPCConfigHandler)
		}

		auth := p.Group("/auth")
		{
			auth.GET("/check", proxy.RPCAuthCheckHandler)
			auth.POST("/check", proxy.RPCAuthCheckHandler)

			auth.POST("/register", proxy.RPCAuthRegisterUserHandler)
			auth.POST("/login", proxy.RPCAuthLoginHandler)
			auth.POST("/apply-controller-session", proxy.RPCAuthCookieHandler)

			auth.GET("/logout", proxy.RPCAuthLogoutHandler)
			auth.POST("/logout", proxy.RPCAuthLogoutHandler)

			auth.POST("/update", proxy.RPCAuthUpdateUserHandler)
			auth.POST("/setpassword", proxy.RPCAuthSetPasswordHandler)

			auth.POST("/elevate-session", proxy.RPCElevateSession)
			auth.POST("/check-elevated-session", proxy.RPCCheckElevatedSession)
			auth.POST("/exit-elevated-session", proxy.RPCExitElevatedSession)
		}

		mcc := p.Group("/mcc")
		mcc.Use(proxy.RPCAuthMiddleware)
		{
			mcc.POST("/enable", func(c *gin.Context) {
				proxy.EnableHandler(c)
				err := k8sClient.InitAuthService(cfg)
				if err != nil {
					log.Sugar().Errorf("Failed to initialize auth service: %v", err)
				}
			})
		}
		k8s := p.Group("/k8s")
		k8s.Use(proxy.RPCAuthMiddleware)
		{
			k8s.POST("/enable", proxy.EnableK8sHandler)
		}

		pool := p.Group("/pool")
		pool.Use(proxy.RPCAuthMiddleware)
		{
			pool.POST("/visible", proxy.SetPoolVisibleHandler)
		}

		clusters := p.Group("/clusters")
		clusters.Use(proxy.RPCAuthMiddleware)
		{
			clusters.GET("/status", proxy.RPCClustersStatus)
			clusters.POST("/status", proxy.RPCClustersStatus)

			clusters.GET("/list", proxy.RPCClustersList)
			clusters.POST("/list", proxy.RPCClustersList)

			clusters.GET("/missingSchedules", proxy.RPCClustersListMissingSchedules)
			clusters.POST("/missingSchedules", proxy.RPCClustersListMissingSchedules)

			clusters.GET("/hosts", proxy.RPCClustersHostList)
			clusters.POST("/hosts", proxy.RPCClustersHostList)
		}

		cmons := p.Group("/controllers")
		cmons.Use(proxy.RPCAuthMiddleware)
		{
			cmons.GET("/status", proxy.RPCControllerStatus)
			cmons.POST("/status", proxy.RPCControllerStatus)
			cmons.POST("/test", proxy.RPCControllerTest)
			cmons.POST("/add", proxy.RPCControllerAdd)
			cmons.POST("/update", proxy.RPCControllerUpdate)
			cmons.POST("/remove", proxy.RPCControllerRemove)
			cmons.GET("/:xid/preferences", proxy.RPCGetControllerPreferencesHandler)
			cmons.POST("/preferences", proxy.RPCControllerPreferencesHandler)
		}

		alarms := p.Group("/alarms")
		alarms.Use(proxy.RPCAuthMiddleware)
		{
			alarms.GET("/status", proxy.RPCAlarmsOverview)
			alarms.POST("/status", proxy.RPCAlarmsOverview)

			alarms.GET("/list", proxy.RPCAlarmsList)
			alarms.POST("/list", proxy.RPCAlarmsList)
		}

		jobs := p.Group("/jobs")
		jobs.Use(proxy.RPCAuthMiddleware)
		{
			jobs.GET("/status", proxy.RPCJobsStatus)
			jobs.POST("/status", proxy.RPCJobsStatus)

			jobs.GET("/list", proxy.RPCJobsList)
			jobs.POST("/list", proxy.RPCJobsList)
		}

		logs := p.Group("/logs")
		logs.Use(proxy.RPCAuthMiddleware)
		{

			logs.GET("/list", proxy.RPCLogsList)
			logs.POST("/list", proxy.RPCLogsList)
		}

		audit := p.Group("/audit")
		audit.Use(proxy.RPCAuthMiddleware)
		{

			audit.GET("/list", proxy.RPCAuditEntryList)
			audit.POST("/list", proxy.RPCAuditEntryList)
		}

		backups := p.Group("/backups")
		backups.Use(proxy.RPCAuthMiddleware)
		{
			backups.GET("/status", proxy.RPCBackupsStatus)
			backups.POST("/status", proxy.RPCBackupsStatus)

			backups.GET("/list", proxy.RPCBackupsList)
			backups.POST("/list", proxy.RPCBackupsList)

			backups.GET("/schedules", proxy.RPCBackupJobsList)
			backups.POST("/schedules", proxy.RPCBackupJobsList)
		}

		admin := p.Group("/admin")
		{
			admin.GET("/reload", proxy.RPCAdminReload)
			admin.POST("/reload", proxy.RPCAdminReload)
		}
	}

	httpServer = &http.Server{
		Handler:      s,
		Addr:         ":" + strconv.Itoa(cfg.Port),
		ReadTimeout:  time.Second * 180,
		WriteTimeout: time.Second * 180,
		IdleTimeout:  time.Second * 180,
	}

	if cfg.AcmeEnabled {
		httpServer.TLSConfig = certManager.TLSConfig()
		log.Sugar().Infof("Starting HTTPS Server with Let's Encrypt on port %d for domains %s", cfg.Port, strings.Join(cfg.AcmeDomains, ", "))
		if err := httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Sugar().Fatalf("HTTPS Server failure on port %d: %s", cfg.Port, err.Error())
		}
	} else {
		if _, err := os.Stat(cfg.TlsCert); os.IsNotExist(err) {
			log.Info("Creating TLS certificate")
			err = CreateTLSCertificate(cfg.TlsCert, cfg.TlsKey)
			if err != nil {
				log.Fatal("Cant generate TLS cert: " + err.Error())
			}
		}

		log.Sugar().Infof("Starting HTTPS Server on port %d", cfg.Port)
		if err := httpServer.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey); err != nil && err != http.ErrServerClosed {
			log.Sugar().Fatalf("HTTPS Server failure on port %d: %s", cfg.Port, err.Error())
		}
	}
}

func Stop() {
	// get logger
	log := zap.L()

	if httpServerPlain != nil {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second*5)
		defer cancel()
		if err := httpServerPlain.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			log.Sugar().Errorf("Failed to shutdown plain http server: %s", err.Error())
		}
		httpServerPlain = nil
	}

	if httpServer == nil {
		return
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Second*5)
	defer cancel()

	log.Sugar().Infof("Shutting down")
	if err := httpServer.Shutdown(ctx); err != nil && err != context.DeadlineExceeded {
		log.Sugar().Fatalf("Failed to shutdown: %s", err.Error())
	}

	httpServer.Close()
	httpServer = nil
}

func unPtr[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
