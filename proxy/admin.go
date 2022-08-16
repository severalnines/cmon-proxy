package proxy
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
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

// RPCAdminReload makes the proxy to reload its configuration
func (p *Proxy) RPCAdminReload(ctx *gin.Context) {
	zap.L().Info(
		fmt.Sprintf("[AUDIT] Configuration reload requested (source %s / %s)",
			ctx.ClientIP(), ctx.Request.UserAgent()))

	if newConfig, err := config.Load(p.r.Config.Filename); newConfig != nil && err == nil {
		// replace the config
		p.r.Config = newConfig
		// sync cmon clients with the new config
		p.r.Sync()
		p.r.GetAllClusterInfo(false)
	}

	ctx.JSON(http.StatusOK, cmonapi.WithResponseData{
		RequestStatus: cmonapi.RequestStatusOk,
	})
}
