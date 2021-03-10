package rpcserver

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"

	"github.com/severalnines/ccx/go/http_handlers"
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
	fmt.Println("xxx")
	s.StaticFS("/static", gin.Dir(path.Join(cfg.FrontendPath, "/static"), false))
	s.StaticFS("/build", gin.Dir(path.Join(cfg.FrontendPath, "/build"), false))
	filepath.Walk(cfg.FrontendPath, func(p string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if strings.Contains(p, "/static/") || strings.Contains(p, "/build/") {
			return nil
		}
		s.StaticFile(path.Base(p), p)
		return nil
	})

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
	if !opts.Opts.DebugWebRpc {
		gin.SetMode(gin.ReleaseMode)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "19051"
	}

	cfg, err := config.Load("ccmgr.yaml")
	if err != nil {
		zap.L().Sugar().Errorf("configfile problem: %s", err.Error())
		// lets continue, with empty config
		cfg = &config.Config{
			// defaults
			Filename: "ccmgr.yaml",
			Logfile:  "ccmgr.log",
		}
	}

	// get logger only after we have lodaded the configuration
	log := zap.L()

	s := gin.New()
	s.Use(ginzap.RecoveryWithZap(log, true))
	s.NoMethod(http_handlers.NoMethod)
	s.Use(http_handlers.Middleware)
	s.OPTIONS("*any", http_handlers.Options)
	s.Use(session.Sessions())

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
		Addr:         ":" + port,
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

	certFile := "server.crt"
	keyFile := "server.key"
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Info("Creating TLS certificate")
		err = CreateTLSCertificate(certFile, keyFile)
		if err != nil {
			log.Fatal("Cant generate TLS cert: " + err.Error())
		}
	}

	log.Sugar().Infof("Starting HTTPS Server on port %s", port)
	if err := hs.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		log.Sugar().Fatalf("HTTPS Server failure on port %s: %s", port, err.Error())
	}
}
