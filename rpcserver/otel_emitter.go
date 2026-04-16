package rpcserver

import (
	"crypto/tls"
	"crypto/x509"
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
	if cfg.OtelMeteringTLSCert != "" && cfg.OtelMeteringTLSKey != "" {
		creds, err := buildClientTLS(cfg.OtelMeteringTLSCert, cfg.OtelMeteringTLSKey, cfg.OtelMeteringTLSCA)
		if err != nil {
			log.Fatalf("[otel-metering] failed to load TLS credentials: %v", err)
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
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caPEM)
		tlsCfg.RootCAs = caPool
	}

	return credentials.NewTLS(tlsCfg), nil
}
