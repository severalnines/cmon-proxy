package main

import (
	"github.com/severalnines/cmon-proxy/logger"
	"github.com/severalnines/cmon-proxy/rpcserver"
	"go.uber.org/zap"
)

// entry point. no logic here.
func main() {
	logger.New(logger.DefaultConfig())
	zap.L().Info("cmon-proxy")
	rpcserver.Start()
}
