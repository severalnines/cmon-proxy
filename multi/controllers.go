package multi

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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi/api"
)

func (p *Proxy) RPCControllerStatus(ctx *gin.Context) {
	retval := api.ControllerStatusList{Controllers: make([]*api.ControllerStatus, 0, 16)}

	// this will ping the controllers
	p.Router(ctx).Ping()

	for _, addr := range p.Router(ctx).Urls() {
		c := p.Router(ctx).Cmon(addr)
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

		if c.Client.Instance.UseLdap {
			if status.Status == api.Ok {
				status.StatusMessage = "LDAP authentication ok."
			} else if status.Status == api.AuthenticationError {
				if len(status.StatusMessage) > 1 {
					status.StatusMessage = "LDAP: " + status.StatusMessage
				} else {
					status.StatusMessage = "LDAP authentication failed."
				}
			}
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
	client := cmon.NewClient(instance, p.Router(nil).Config.Timeout)
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
	if instance.UseLdap {
		if retval.Status == api.Ok {
			retval.StatusMessage = "LDAP authentication ok."
		} else if retval.Status == api.AuthenticationError {
			if len(retval.StatusMessage) > 1 {
				retval.StatusMessage = "LDAP: " + retval.StatusMessage
			} else {
				retval.StatusMessage = "LDAP authentication failed."
			}
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

	if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
		if authenticatedUser.LdapUser {
			cmonapi.CtxWriteError(ctx, fmt.Errorf("LDAP users cant add controllers"), http.StatusForbidden)
			return
		}
	}

	if err := ctx.BindJSON(&req); err != nil || req.Controller == nil {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	resp.Controller = p.pingOne(req.Controller)

	if err := p.Router(nil).Config.AddController(req.Controller, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	// it is going to refresh everything
	p.Refresh()

	ctx.JSON(http.StatusOK, &resp)
}

func (p *Proxy) RPCControllerUpdate(ctx *gin.Context) {
	var req api.AddControllerRequest
	var resp api.AddControllerResponse

	if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
		if authenticatedUser.LdapUser {
			cmonapi.CtxWriteError(ctx, fmt.Errorf("LDAP users cant update controllers"), http.StatusForbidden)
			return
		}
	}

	if err := ctx.BindJSON(&req); err != nil || req.Controller == nil {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	resp.Controller = p.pingOne(req.Controller)

	// remove & add it again
	p.Router(nil).Config.RemoveController(req.Controller.Url, false)
	if err := p.Router(nil).Config.AddController(req.Controller, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	// it is going to refresh everything
	p.Refresh()

	ctx.JSON(http.StatusOK, &resp)
}

func (p *Proxy) RPCControllerRemove(ctx *gin.Context) {
	var req api.RemoveControllerRequest

	if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
		if authenticatedUser.LdapUser {
			cmonapi.CtxWriteError(ctx, fmt.Errorf("LDAP users cant remove controllers"), http.StatusForbidden)
			return
		}
	}

	if err := ctx.BindJSON(&req); err != nil || len(req.Url) < 1 {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	if err := p.Router(nil).Config.RemoveController(req.Url, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	// it is going to refresh everything
	p.Refresh()

	ctx.JSON(http.StatusOK, cmonapi.NewError(cmonapi.RequestStatusOk, "The controller is removed."))
}

func (p *Proxy) RPCProxyRequest(ctx *gin.Context, controllerId, method string, reqBytes []byte) {
	var err error
	// do we need this here? it could do (re-)auth and things like that
	// p.r.Ping()

	authenticatedUserName := "<anonymous>"
	if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
		authenticatedUserName = authenticatedUser.Username
	}
	fmt.Println("User", authenticatedUserName, "calls", ctx.Request.URL.Path)

	for _, addr := range p.Router(ctx).Urls() {
		c := p.Router(ctx).Cmon(addr)
		if c == nil || c.Client == nil {
			continue
		}

		if c.Client.ControllerID() == controllerId {
			resBytes, err := c.Client.RequestBytes(ctx.Request.URL.EscapedPath(), reqBytes, false)
			if err != nil {
				break
			}
			// return the data as it is
			ctx.Data(http.StatusOK, "application/json", resBytes)
			return
		}
	}

	// in case we didn't found
	var resp cmonapi.WithResponseData
	if err == nil {
		resp.RequestStatus = cmonapi.RequestStatusObjectNotFound
		resp.ErrorString = "couldn't find controller with the specified id"
	} else {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "error while communicating to cmon:" + err.Error()
	}
	ctx.JSON(http.StatusNotFound, resp)
}
