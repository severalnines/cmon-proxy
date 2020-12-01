package main

import (
	"github.com/severalnines/bar-pkg/logger"
	"github.com/severalnines/cmon-proxy/rpcserver"
	"go.uber.org/zap"
)

// entry point. no logic here.
func main() {
	zap.ReplaceGlobals(logger.Default())
	zap.L().Info("cmon-proxy")
	rpcserver.Start()
}
