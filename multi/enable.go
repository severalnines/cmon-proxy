package multi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/multi/api"
)

func (p *Proxy) RPCEnableHandler(ctx *gin.Context) {
	var resp api.EnableResponse
	p.cfg.EnableMcc(true)
	p.cfg.Save();
	ctx.JSON(http.StatusOK, resp)
}