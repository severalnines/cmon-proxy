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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"

	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/opts"
	"github.com/severalnines/cmon-proxy/proxy"
	"github.com/severalnines/cmon-proxy/rpcserver/session"
	"go.uber.org/zap"
)

var (
	httpServer *http.Server
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
		body, _ := ioutil.ReadAll(c.Copy().Request.Body)
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

func serveFrontend(s *gin.Engine, cfg *config.Config) {
	s.StaticFS("/static", gin.Dir(path.Join(cfg.FrontendPath, "/static"), false))
	s.StaticFS("/build", gin.Dir(path.Join(cfg.FrontendPath, "/build"), false))
	err := filepath.Walk(cfg.FrontendPath, func(p string, info os.FileInfo, err error) error {
		if info == nil || err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.Contains(p, "/static/") || strings.Contains(p, "/build/") {
			return nil
		}
		s.StaticFile(path.Base(p), p)
		return nil
	})
	if err != nil {
		zap.L().Sugar().Warnf("Can't serve static HTML files: %s", err.Error())
	}

	// and redirect anything to index.html
	s.NoRoute(func(c *gin.Context) {
		if c.Request == nil && c.Request.URL == nil &&
			strings.HasPrefix(c.Request.URL.Path, "/proxy") &&
			!strings.HasPrefix(c.Request.URL.Path, "/v2") {
			var resp cmonapi.WithResponseData
			resp.RequestStatus = cmonapi.RequestStatusObjectNotFound
			resp.ErrorString = "path not found"

			c.JSON(http.StatusNotFound, resp)
			return
		}
		// everything else shall go to web
		c.File(path.Join(cfg.FrontendPath, "index.html"))
	})
}

// Start is starting the service
func Start(cfg *config.Config) {
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

	proxy, err := proxy.New(cfg)
	if err != nil {
		log.Sugar().Fatalf("initialization problem: %s", err.Error())
	}
	// do initial connection to the nodes
	proxy.Authenticate()

	// to serve the static files
	serveFrontend(s, cfg)

	s.Use(func(ctx *gin.Context) {
		if ctx.Request == nil || ctx.Request.URL == nil ||
			!strings.HasPrefix(ctx.Request.URL.Path, "/v2") {
			ctx.Next()
			return
		}
		// Proxy requests to cmon (must have controller_id)
		var controllerId cmonapi.WithControllerID
		method := ctx.Request.Method
		jsonData, err := ioutil.ReadAll(ctx.Request.Body)

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
			ctx.Abort()
			return
		}
		if len(controllerId.ControllerID) < 1 {
			var resp cmonapi.WithResponseData
			resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
			resp.ErrorString = "missing controller_id from request"
			ctx.JSON(http.StatusBadRequest, resp)
			ctx.Abort()
			return
		}

		proxy.RPCProxyRequest(ctx, controllerId.ControllerID, method, jsonData)
		ctx.Abort()
	})

	// aggregating APIs for WEB UI v0
	p := s.Group("/proxy")
	{
		auth := p.Group("/auth")
		{
			auth.GET("/check", proxy.RPCAuthCheckHandler)
			auth.POST("/check", proxy.RPCAuthCheckHandler)

			auth.POST("/login", proxy.RPCAuthLoginHandler)

			auth.GET("/logout", proxy.RPCAuthLogoutHandler)
			auth.POST("/logout", proxy.RPCAuthLogoutHandler)

			auth.POST("/update", proxy.RPCAuthUpdateUserHandler)
			auth.POST("/setpassword", proxy.RPCAuthSetPasswordHandler)
		}

		clusters := p.Group("/clusters")
		clusters.Use(proxy.RPCAuthMiddleware)
		{
			clusters.GET("/status", proxy.RPCClustersStatus)
			clusters.POST("/status", proxy.RPCClustersStatus)

			clusters.GET("/list", proxy.RPCClustersList)
			clusters.POST("/list", proxy.RPCClustersList)

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
