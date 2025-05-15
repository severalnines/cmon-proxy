package multi

import (
	"time"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/multi/api"
	"github.com/severalnines/cmon-proxy/multi/router"
)

func (p *Proxy) EnableHandler(ctx *gin.Context) {
	var req api.EnableMccRequest
	var resp api.EnableMccResponse
	resp.WithResponseData = &cmonapi.WithResponseData{
		RequestStatus: cmonapi.RequestStatusOk,
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
	}

	cfg := p.r[router.DefaultRouter].Config

	if cfg == nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Config is not loaded"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if len(cfg.SingleController) < 1 {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Multi-controller is already enabled"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	if err := ctx.BindJSON(&req); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
		resp.ErrorString = "Invalid request " + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	// Handle user registration if provided
	if req.User != nil {
		// We are not allowing to register more than one admin user
		if len(cfg.Users) > 0 {
			resp.RequestStatus = cmonapi.RequestStatusAccessDenied
			resp.ErrorString = "Admin user already exists"
			ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
			return
		}

		proxyUser := req.User.Copy(true)
		proxyUser.PasswordHash = ""
		if len(req.User.Password) < 1 {
			resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
			resp.ErrorString = "Invalid password"
			ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
			return
		}
		if err := proxyUser.SetPassword(req.User.Password); err != nil {
			resp.RequestStatus = cmonapi.RequestStatusInvalidRequest
			resp.ErrorString = "Invalid password"
			ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
			return
		}

		if err := cfg.AddUser(proxyUser); err != nil {
			resp.RequestStatus = cmonapi.RequestStatusUnknownError
			resp.ErrorString = "Failed to add user: " + err.Error()
			ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
			return
		}
	}

	if req.LdapEnabled {
		cfg.SetLdapEnabled(cfg.SingleController, true, true)
	} else {
		cfg.SetLdapEnabled(cfg.SingleController, false, true)
	}

	// Enable MCC mode
	cfg.SingleController = ""
	if err := cfg.Save(); err != nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Failed to save config " + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
}
