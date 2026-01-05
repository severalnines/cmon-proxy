package multi

import (
	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/multi/api"
	"github.com/severalnines/cmon-proxy/multi/router"
)

func (p *Proxy) SetPoolVisibleHandler(ctx *gin.Context) {
	var req api.SetPoolVisibleRequest
	var resp api.SetPoolVisibleResponse
	resp.WithResponseData = &cmonapi.WithResponseData{
		RequestStatus: cmonapi.RequestStatusOk,
	}

	cfg := p.r[router.DefaultRouter].Config

	if cfg == nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Config is not loaded"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if err := ctx.BindJSON(&req); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Invalid request " + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if cfg.PoolVisible && req.Visible {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Pool is already visible"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if !cfg.PoolVisible && !req.Visible {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Pool is already hidden"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	cfg.PoolVisible = req.Visible

	if err := cfg.Save(); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Failed to save config " + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}

