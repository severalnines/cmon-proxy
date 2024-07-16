package main

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
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/logger"
	"github.com/severalnines/cmon-proxy/opts"
	"github.com/severalnines/cmon-proxy/rpcserver"
	"go.uber.org/zap"
)

// entry point. no logic here.
func main() {
	logger.New(logger.DefaultConfig())
	zap.L().Info("ClusterControl Manager v2.2")

	opts.Init()
	if !opts.Opts.DebugWebRpc {
		gin.SetMode(gin.ReleaseMode)
	}

	config, err := config.Load(path.Join(opts.Opts.BaseDir, "ccmgr.yaml"))
	if err != nil {
		// we have nice default values from ::Load() method
		zap.L().Sugar().Warnf("configfile problem: %s", err.Error())
	}

	config.Upgrade()

	// Stop on signals
	signals := make(chan os.Signal, 1)
	signal.Notify(signals,
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGHUP)
	go func() {
		for sig := range signals {
			zap.L().Sugar().Infof("Received signal (%s)", sig.String())
			rpcserver.Stop()
		}
	}()

	// Start server
	rpcserver.Start(config)
}
