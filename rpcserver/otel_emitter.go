package rpcserver

import (
	"time"

	"github.com/severalnines/cmon-proxy/config"
	cmonotel "github.com/severalnines/cmon-proxy/otel"
	"go.uber.org/zap"
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

	provider := cmonotel.NewRouterAdapter(proxy.DefaultRouter())
	otelEmitter = cmonotel.NewEmitter(provider, endpoint, interval, instanceID)
	otelEmitter.Start()

	log.Infof("[otel-metering] emitter started (endpoint=%s, interval=%s, instance=%s)", endpoint, interval, instanceID)
}
