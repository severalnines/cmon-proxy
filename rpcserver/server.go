package rpcserver

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/severalnines/bar-user-auth-api/auth"
	"github.com/severalnines/bar-user-auth-api/session"
	"github.com/severalnines/ccx/go/http_handlers"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/proxy"
	"go.uber.org/zap"
)

// Start is starting the service
func Start() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "19051"
	}
	logger := zap.L()
	s := gin.New()
	s.Use(ginzap.Ginzap(logger, time.RFC3339, true))
	s.Use(ginzap.RecoveryWithZap(logger, true))
	s.NoRoute(http_handlers.NoRoute)
	s.NoMethod(http_handlers.NoMethod)
	s.Use(http_handlers.Middleware)
	s.OPTIONS("*any", http_handlers.Options)
	s.Use(session.Sessions())
	s.Use(auth.Check)
	config, err := config.Load("cmon-proxy.cnf")
	if err != nil {
		logger.Sugar().Fatalf("configfile problem: %s", err.Error())
	}
	multiClient, err := proxy.NewMultiClient(config)
	if err != nil {
		logger.Sugar().Fatalf("initialization problem: %s", err.Error())
	}

	v1 := s.Group("/v2")
	{
		v1.POST("/auth", multiClient.RPCAuthenticate)
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
			logger.Info("Shutting down",
				zap.Stringer("signal", sig))
			if err := hs.Shutdown(ctx); err != nil {
				logger.Fatal("Failed to shutdown",
					zap.Stringer("signal", sig),
					zap.Error(err))
			}
		}
	}()

	var certFile, keyFile string
	if _, err := os.Stat("server.crt"); os.IsNotExist(err) {
		logger.Info("Creating TLS certificate")
		certFile, keyFile, err = CreateTLSCertificate("server")
		if err != nil {
			logger.Fatal("Cant generate TLS cert: " + err.Error())
		}
	}

	logger.Info("Starting HTTPS Server",
		zap.String("port", port))
	if err := hs.ListenAndServeTLS(certFile, keyFile); err != nil {
		logger.Fatal("HTTPS Server failure",
			zap.String("port", port),
			zap.Error(err))
	}
}
