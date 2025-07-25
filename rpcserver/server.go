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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/gzip"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"

	"github.com/severalnines/cmon-proxy/config"
	k8s "github.com/severalnines/cmon-proxy/k8s"
	"github.com/severalnines/cmon-proxy/multi"
	"github.com/severalnines/cmon-proxy/opts"
	"github.com/severalnines/cmon-proxy/rpcserver/session"
	"go.uber.org/zap"
)

var (
	httpServer *http.Server
	proxy      *multi.Proxy
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

func serveStaticOrIndex(c *gin.Context, path string) {
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
	c.Header("Cache-Control", "public, max-age=31536000")
	c.Header("Content-Length", fmt.Sprintf("%d", info.Size()))
	lastModified := info.ModTime().UTC().Format(http.TimeFormat)
	c.Header("Last-Modified", lastModified)
	etag := generateETag(info)
	c.Header("ETag", etag)

	c.File(filePath)
	c.Abort()
}

func generateETag(info os.FileInfo) string {
	hash := md5.New()
	hash.Write([]byte(fmt.Sprintf("%s-%d-%d", info.Name(), info.Size(), info.ModTime().Unix())))
	return fmt.Sprintf(`"%x"`, hash.Sum(nil))
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
	s.Use(gzip.Gzip(gzip.BestSpeed))
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
				if cfg.Users == nil || len(cfg.Users) < 1 {
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
				
				// Forward the original client's IP address
				clientIP := c.ClientIP()
				req.Header.Set("X-Forwarded-For", clientIP)
				req.Header.Set("X-Real-IP", clientIP)
				
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
			serveStaticOrIndex(c, cleanPath)
		}
	})

	return nil
}

func forwardToCmon(ctx *gin.Context) {
	// Proxy requests to cmon (must have controller_id)
	var controllerId cmonapi.WithControllerID
	method := ctx.Request.Method
	jsonData, err := io.ReadAll(ctx.Request.Body)

	if err == nil {
		err = json.Unmarshal(jsonData, &controllerId)
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
		_ = json.Unmarshal(jsonData, &controllerId)
	}
	if err != nil {
		var resp cmonapi.WithResponseData
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "couldn't read request body: " + err.Error()
		ctx.JSON(http.StatusBadRequest, resp)
		return
	}
	if !controllerId.HasID() {
		var resp cmonapi.WithResponseData
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "missing xid or controller_id from request"
		ctx.JSON(http.StatusBadRequest, resp)
		return
	}

	proxy.RPCProxyRequest(ctx, controllerId.GetID(), method, jsonData)
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

// Start is starting the service
func Start(cfg *config.Config) {
	var err error
	// get logger
	log := zap.L()

	if httpServer != nil {
		log.Sugar().Fatalln("rpcserver is already running")
		return
	}

	s := gin.New()
	s.Use(ginzap.RecoveryWithZap(log, true))
	s.NoMethod(func(c *gin.Context) { c.JSON(http.StatusMethodNotAllowed, gin.H{"err": "method not allowed"}) })
	s.Use(func(c *gin.Context) {
		// Middleware attaches CORS (access-control-allow-*) headers
		// to gin.Context on every request to allow cross-domain
		// requests from the frontend.
		origin := c.GetHeader("origin")
		if origin == "" {
			origin = "*"
		}
		c.Header("access-control-allow-origin", origin)
		c.Header("access-control-allow-credentials", "true")
		c.Next()
	})
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

	multi.StartSessionCleanupScheduler(proxy)

	s.Use(func(c *gin.Context) {
		// Based on PEN test report https://severalnines.atlassian.net/browse/CLUS-4437
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("X-Content-Type-Options", "nosniff")
	})

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

	k8sClient, err := k8s.NewK8sProxyClient(cfg)
	if err != nil {
		log.Sugar().Fatalf("initialization problem: %s", err.Error())
	}

	single := s.Group("/single")
	{
		single.POST("/v2/*any", proxy.PRCProxySingleController)
		single.GET("/v2/*any", proxy.PRCProxySingleController)
		k8s := single.Group("/k8s")
		{
			k8sProxyHandler := func(c *gin.Context) {
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
		if cfg.SingleController == "" {
			v2.Use(proxy.RPCAuthMiddleware)
		}
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

func Stop() {
	// get logger
	log := zap.L()

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
