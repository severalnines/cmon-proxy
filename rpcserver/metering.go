package rpcserver

// Copyright 2026 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"net/http"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/metering"
	"go.uber.org/zap"
)

const defaultMeteringInterval = time.Hour

func initMetering(cfg *config.Config) {
	log := zap.L().Sugar()

	// Determine DB path.
	dbPath := cfg.MeteringDBPath
	if dbPath == "" {
		basedir := filepath.Dir(cfg.Filename)
		if basedir == "" || basedir == "." {
			basedir = "."
		}
		dbPath = filepath.Join(basedir, "metering.db")
	}

	// Parse interval.
	meteringInterval = defaultMeteringInterval
	if cfg.MeteringInterval != "" {
		d, err := time.ParseDuration(cfg.MeteringInterval)
		if err != nil {
			log.Warnf("[metering] invalid metering_interval %q, using default %s: %v", cfg.MeteringInterval, defaultMeteringInterval, err)
		} else {
			meteringInterval = d
		}
	}

	// Open storage.
	var err error
	meteringStorage, err = metering.NewSQLiteBackend(dbPath)
	if err != nil {
		log.Errorf("[metering] failed to open database at %s: %v (metering disabled)", dbPath, err)
		return
	}

	log.Infof("[metering] database opened at %s", dbPath)

	// Create collector using the default router.
	provider := metering.NewRouterAdapter(proxy.DefaultRouter())
	meteringCollector = metering.NewCollector(meteringStorage, provider, meteringInterval)
	meteringCollector.Start()

	log.Infof("[metering] collector started with interval %s", meteringInterval)
}

func handleMeteringStatus(ctx *gin.Context) {
	if meteringStorage == nil {
		ctx.JSON(http.StatusOK, &metering.StatusResponse{
			CollectorRunning: false,
		})
		return
	}

	resp, err := metering.GetStatus(ctx.Request.Context(), meteringStorage, meteringCollector != nil, meteringInterval)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, resp)
}
