package multi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/multi/api"
)

func (p *Proxy) RPCConfigHandler(ctx *gin.Context) {
	var resp api.ConfigResponse

	resp.Config.FetchBackupsDays = &p.cfg.FetchBackupDays
	resp.Config.FetchJobsHours = &p.cfg.FetchJobsHours

	ctx.JSON(http.StatusOK, resp)
}