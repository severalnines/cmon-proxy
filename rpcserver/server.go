package rpcserver

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"

	//"github.com/severalnines/bar-user-auth-api/auth"
	"github.com/severalnines/bar-user-auth-api/session"
	"github.com/severalnines/ccx/go/http_handlers"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/opts"
	"github.com/severalnines/cmon-proxy/proxy"
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

	// log the incoming request
	body, _ := ioutil.ReadAll(c.Copy().Request.Body)
	logger.Debugf("Web request [%s] %s %s:\n%s",
		c.ClientIP(), c.Request.Method, c.Request.RequestURI, string(body))

	// call handlers
	c.Next()

	// check elapsed time
	elapsed := time.Since(start)

	// and then log the reply too
	logger.Debugf("Web reply   [%s] (elapsed: %dms) status %d:\n%s",
		c.ClientIP(), int64(elapsed/time.Millisecond), c.Copy().Writer.Status(), bodyWriter.responseBody.String())
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

	config, err := config.Load("cmon-proxy.yaml")
	if err != nil {
		zap.L().Sugar().Fatalf("configfile problem: %s", err.Error())
	}

	// get logger only after we have lodaded the configuration
	log := zap.L()

	s := gin.New()
	s.Use(ginzap.RecoveryWithZap(log, true))
	s.NoRoute(http_handlers.NoRoute)
	s.NoMethod(http_handlers.NoMethod)
	s.Use(http_handlers.Middleware)
	s.OPTIONS("*any", http_handlers.Options)
	s.Use(session.Sessions())

	/*
		s.Use(auth.Check)
	*/

	if opts.Opts.DebugWebRpc {
		s.Use(WebRpcDebugMiddleware)
	}

	zap.L().Info("Starting RPC service")

	router, err := proxy.NewRouter(config)
	if err != nil {
		log.Sugar().Fatalf("initialization problem: %s", err.Error())
	}
	// do initial connection to the nodes
	router.Authenticate()

	// kinda cmon compatible apis.. *experimental*
	v2 := s.Group("/v2")
	{
		v2.POST("/auth", router.RPCAuthenticate)
	}

	// aggregating APIs for WEB UI v0
	p := s.Group("/proxy")
	{
		clusters := p.Group("/clusters")
		{
			clusters.GET("/status", router.RPCClustersStatus)
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
