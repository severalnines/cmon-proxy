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
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/proxy/api"
)

func (p *Proxy) RPCControllerStatus(ctx *gin.Context) {
	retval := api.ControllerStatusList{Controllers: make([]*api.ControllerStatus, 0, 16)}

	// this will ping the controllers
	p.r.Ping()

	for _, addr := range p.r.Urls() {
		c := p.r.Cmon(addr)
		if c == nil {
			continue
		}

		// get it from cache
		mtx.Lock()
		status := controllerStatusCache[addr]
		mtx.Unlock()

		if status == nil {
			status = &api.ControllerStatus{
				Url:         addr,
				FrontendUrl: c.Client.Instance.FrontendUrl,
			}
		}

		status.Name = c.Client.Instance.Name
		status.ControllerID = c.Client.ControllerID()
		status.Status = api.Ok
		status.LastUpdated.T = time.Now()

		if c.PingError != nil {
			status.Status = api.Failed
			status.StatusMessage = c.PingError.Error()

			// lets look if the root cause is auth related
			if c.Client.RequestStatus() == cmonapi.RequestStatusAccessDenied ||
				c.Client.RequestStatus() == cmonapi.RequestStatusAuthRequired {
				status.Status = api.AuthenticationError
			}
		}

		resp := c.PingResponse
		if resp != nil && len(resp.Version) > 0 {
			// prefer the version from the ping response
			status.Version = resp.Version
		} else if len(c.Client.ServerVersion()) > 0 {
			// but we can go with the one from server header too
			status.Version = c.Client.ServerVersion()
		}

		if status.Status == api.Ok {
			status.LastSeen.T = time.Now()
		}

		// persist in cache for later use
		mtx.Lock()
		controllerStatusCache[addr] = status
		mtx.Unlock()

		retval.Controllers = append(retval.Controllers, status)
	}

	ctx.JSON(http.StatusOK, retval)
}

func (p *Proxy) pingOne(instance *config.CmonInstance) *api.ControllerStatus {
	client := cmon.NewClient(instance, p.r.Config.Timeout)
	var resp *cmonapi.PingResponse
	err := client.Authenticate()
	if err != nil {
		resp, err = client.Ping()
	}

	retval := &api.ControllerStatus{
		ControllerID: client.ControllerID(),
		Version:      client.ServerVersion(),
		Url:          instance.Url,
		Name:         instance.Name,
		Status:       api.Ok,
	}
	if resp != nil && len(resp.Version) > 0 {
		retval.Version = resp.Version
	}
	if err != nil {
		retval.StatusMessage = err.Error()
		retval.Status = api.Failed

		// lets look if the root cause is auth related
		if client.RequestStatus() == cmonapi.RequestStatusAccessDenied ||
			client.RequestStatus() == cmonapi.RequestStatusAuthRequired {
			retval.Status = api.AuthenticationError
		}
	}
	return retval
}

func (p *Proxy) RPCControllerTest(ctx *gin.Context) {
	var req api.AddControllerRequest
	var resp api.AddControllerResponse
	if err := ctx.BindJSON(&req); err != nil || req.Controller == nil {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	resp.Controller = p.pingOne(req.Controller)

	ctx.JSON(http.StatusOK, &resp)
}

func (p *Proxy) RPCControllerAdd(ctx *gin.Context) {
	var req api.AddControllerRequest
	var resp api.AddControllerResponse
	if err := ctx.BindJSON(&req); err != nil || req.Controller == nil {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	resp.Controller = p.pingOne(req.Controller)

	if err := p.r.Config.AddController(req.Controller, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	// also call authenticate, this will add the new client, it can be done delayed in a thread
	go func() {
		p.r.Authenticate()
	}()

	ctx.JSON(http.StatusOK, &resp)
}

func (p *Proxy) RPCControllerRemove(ctx *gin.Context) {
	var req api.RemoveControllerRequest
	if err := ctx.BindJSON(&req); err != nil || len(req.Url) < 1 {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	if err := p.r.Config.RemoveController(req.Url, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	// also call authenticate, this will drop the existing client, it can be done delayed in a thread
	go func() {
		p.r.Authenticate()
	}()

	ctx.JSON(http.StatusOK, cmonapi.NewError(cmonapi.RequestStatusOk, "The controller is removed."))
}
