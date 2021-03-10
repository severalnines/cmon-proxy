package proxy

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
