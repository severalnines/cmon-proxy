package rpcserver

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/severalnines/cmon-proxy/config"
	cmonotel "github.com/severalnines/cmon-proxy/otel"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultOtelInterval = time.Hour

func initOtelEmitter(cfg *config.Config) {
	log := zap.L().Sugar()

	endpoint := cfg.OtelMeteringEndpoint
	if endpoint == "" {
		endpoint = "localhost:4317"
	}

	interval := defaultOtelInterval
	if cfg.OtelMeteringInterval != "" {
		d, err := time.ParseDuration(cfg.OtelMeteringInterval)
		if err != nil {
			log.Warnf("[otel-metering] invalid interval %q, using default %s: %v", cfg.OtelMeteringInterval, defaultOtelInterval, err)
		} else {
			interval = d
		}
	}

	instanceID := cfg.OtelMeteringInstance
	if instanceID == "" {
		instanceID = "cmon-proxy"
	}

	// Configure gRPC credentials.
	var dialOpts []grpc.DialOption
	if cfg.OtelMeteringTLSCert != "" || cfg.OtelMeteringTLSKey != "" || cfg.OtelMeteringTLSCA != "" {
		creds, err := buildClientTLS(cfg.OtelMeteringTLSCert, cfg.OtelMeteringTLSKey, cfg.OtelMeteringTLSCA)
		if err != nil {
			// Metering is non-critical — a bad cert shouldn't kill the whole
			// cmon-proxy process. Log and skip starting the emitter.
			log.Errorf("[otel-metering] failed to load TLS credentials; emitter disabled: %v", err)
			return
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
		log.Info("[otel-metering] gRPC TLS enabled")
	} else if cfg.OtelMeteringInsecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Default: use system CA pool for server verification.
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	}

	// Ensure the Router is synced and authenticated before the emitter starts.
	defaultRouter := proxy.DefaultRouter()
	defaultRouter.Authenticate()

	provider := cmonotel.NewRouterAdapter(defaultRouter)
	otelEmitter = cmonotel.NewEmitter(provider, endpoint, interval, instanceID, dialOpts...)
	otelEmitter.Start()

	log.Infof("[otel-metering] emitter started (endpoint=%s, interval=%s, instance=%s)", endpoint, interval, instanceID)
}

// buildClientTLS creates gRPC client TLS credentials.
func buildClientTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	tlsCfg := &tls.Config{}

	if certFile == "" && keyFile != "" || certFile != "" && keyFile == "" {
		return nil, fmt.Errorf("otel metering TLS requires both client cert and key")
	}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA cert %q: no PEM certs found", caFile)
		}
		tlsCfg.RootCAs = caPool
	}

	return credentials.NewTLS(tlsCfg), nil
}
