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
	"github.com/severalnines/cmon-proxy/logger"
	"github.com/severalnines/cmon-proxy/proxy"
	"go.uber.org/zap"
)

// Start is starting the service
func Start() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "19051"
	}

	config, err := config.Load("cmon-proxy.cnf")
	if err != nil {
		zap.L().Sugar().Fatalf("configfile problem: %s", err.Error())
	}

	log := zap.L()
	s := gin.New()
	s.Use(logger.GinZapFunc())
	s.Use(ginzap.RecoveryWithZap(log, true))
	s.NoRoute(http_handlers.NoRoute)
	s.NoMethod(http_handlers.NoMethod)
	s.Use(http_handlers.Middleware)
	s.OPTIONS("*any", http_handlers.Options)
	s.Use(session.Sessions())
	s.Use(auth.Check)

	multiClient, err := proxy.NewMultiClient(config)
	if err != nil {
		log.Sugar().Fatalf("initialization problem: %s", err.Error())
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
