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
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
		if c.Request == nil && c.Request.URL == nil && strings.HasPrefix(c.Request.URL.Path, "/proxy") {
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
func Start() {
	opts.Init()
	if !opts.Opts.DebugWebRpc {
		gin.SetMode(gin.ReleaseMode)
	}

	cfg, err := config.Load(path.Join(opts.Opts.BaseDir, "ccmgr.yaml"))
	if err != nil {
		// we have nice default values from ::Load() method
		zap.L().Sugar().Warnf("configfile problem: %s", err.Error())
	}

	// get logger only after we have lodaded the configuration
	log := zap.L()

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
		c.Header("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE")
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

	hs := &http.Server{
		Handler:      s,
		Addr:         ":" + strconv.Itoa(cfg.Port),
		ReadTimeout:  time.Second * 180,
		WriteTimeout: time.Second * 180,
		IdleTimeout:  time.Second * 180,
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals,
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGHUP)
	go func() {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second*5)
		defer cancel()
		for sig := range signals {
			log.Sugar().Infof("Shutting down (%s)", sig.String())
			if err := hs.Shutdown(ctx); err != nil && err != context.DeadlineExceeded {
				log.Sugar().Fatalf("Failed to shutdown (%s): %s", sig.String(), err.Error())
			}
		}
	}()

	if _, err := os.Stat(cfg.TlsCert); os.IsNotExist(err) {
		log.Info("Creating TLS certificate")
		err = CreateTLSCertificate(cfg.TlsCert, cfg.TlsKey)
		if err != nil {
			log.Fatal("Cant generate TLS cert: " + err.Error())
		}
	}

	log.Sugar().Infof("Starting HTTPS Server on port %d", cfg.Port)
	if err := hs.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey); err != nil && err != http.ErrServerClosed {
		log.Sugar().Fatalf("HTTPS Server failure on port %d: %s", cfg.Port, err.Error())
	}
}
