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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi/api"
	"github.com/severalnines/cmon-proxy/multi/router"
)

func (p *Proxy) RPCControllerStatus(ctx *gin.Context) {
	var req api.ControllerStatusRequest

	/* check license is only possible via getAllClusterInfo call which might be slow
	 * so we aren't doing it here by default, only if explicitly required,
	 * however if the info is already available from cache the license info will be
	 * included in the response anyways
	 */
	forceLicenseCheck := false
	if err := ctx.BindJSON(&req); err == nil {
		forceLicenseCheck = req.ForceLicenseCheck
	}

	retval := api.ControllerStatusList{Controllers: make([]*api.ControllerStatus, 0, 16)}

	// this will ping the controllers
	p.Router(ctx).Ping()

	if forceLicenseCheck {
		// make sure license info is re-freshed
		p.Router(ctx).GetAllClusterInfo(false)
	}

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
				Ldap:        c.Client.Instance.UseLdap,
			}
		}

		status.Name = c.Client.Instance.Name
		status.ControllerID = c.ControllerID()
		status.Xid = c.Xid()
		status.Status = api.Ok
		status.LastUpdated.T = time.Now()

		// NOTE: license data is only available after getAllClusterInfo has been requested
		if c.Clusters != nil && c.Clusters.CmonLicense != nil {
			status.License = c.Clusters.CmonLicense
			status.LicenseCheck = c.Clusters.CmonLicenseCheck
		}

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
				if len(status.StatusMessage) > 1 && !strings.HasPrefix(status.StatusMessage, "LDAP") {
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
		Xid:          instance.Xid,
		ControllerID: client.ControllerID(),
		Version:      client.ServerVersion(),
		Url:          instance.Url,
		Name:         instance.Name,
		Ldap:         instance.UseLdap,
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
	if err := req.Controller.Verify(); err != nil {
		cmonapi.CtxWriteError(ctx, err)
	}

	// remove & add it again
	if err := p.Router(nil).Config.RemoveController(req.Controller.Url, false); err != nil {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "Controller not found ("+err.Error()+")"))
		return
	}
	if err := p.Router(nil).Config.AddController(req.Controller, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	resp.Controller = p.pingOne(req.Controller)

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

		// this accepts both xid or controller_id
		if c.MatchesID(controllerId) {
			var resBytes []byte
			parsed := make(map[string]interface{})
			resBytes, err = c.Client.RequestBytes(ctx.Request.URL.EscapedPath(), reqBytes, false)
			if err != nil {
				break
			}
			if err = json.Unmarshal(resBytes, &parsed); err != nil || len(parsed) < 1 {
				// return the data as it is
				ctx.Data(http.StatusOK, "application/json", resBytes)
			}

			// NOTE: controller_id must be already there set & sent by cmon
			parsed["xid"] = c.Xid()
			resBytes, err = json.Marshal(parsed)
			if err != nil {
				break
			}
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

func (p *Proxy) RPCProxyMany(ctx *gin.Context, xIds []string, method string, reqBytes []byte) {
	var err error
	// map if xid <-> cmon replies
	var repliesMtx sync.Mutex
	replies := make(map[string]json.RawMessage)

	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, router.ParallelLevel)

	for _, addr := range p.Router(ctx).Urls() {
		c := p.Router(ctx).Cmon(addr)
		if c == nil || c.Client == nil {
			continue
		}

		passesXidFilter := false
		for _, xid := range xIds {
			if c.MatchesID(xid) {
				passesXidFilter = true
				break
			}
		}
		// this specific Cmon wasn't requested.. skip it
		if !passesXidFilter {
			continue
		}

		// paralell authentication to the cmons
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			var resBytes []byte
			parsed := make(map[string]interface{})
			resBytes, err = c.Client.RequestBytes(ctx.Request.URL.EscapedPath(), reqBytes, false)
			if err != nil {
				var resp cmonapi.WithResponseData
				if err != nil {
					resp.RequestStatus = cmonapi.RequestStatusUnknownError
					resp.ErrorString = "error while communicating to cmon:" + err.Error()
				}
				repliesMtx.Lock()
				replies[c.Xid()], err = json.Marshal(parsed)
				repliesMtx.Unlock()

			}
			if err = json.Unmarshal(resBytes, &parsed); err != nil || len(parsed) < 1 {
				replyData := make(map[string]interface{})
				replyData["xid"] = c.Xid()
				replyData["data"] = resBytes // this isn't JSon just some RAW reply
				repliesMtx.Lock()
				replies[c.Xid()], err = json.Marshal(replyData)
				repliesMtx.Unlock()
			}

			// NOTE: controller_id must be already there set & sent by cmon
			parsed["xid"] = c.Xid()
			repliesMtx.Lock()
			replies[c.Xid()], err = json.Marshal(parsed)
			repliesMtx.Unlock()
		}()
	}
	wg.Wait()

	// add missing status where the reply is missing
	for _, xid := range xIds {
		if _, found := replies[xid]; !found {
			replies[xid], _ = json.Marshal(&cmonapi.WithResponseData{
				RequestStatus: cmonapi.RequestStatusObjectNotFound,
				ErrorString:   "No cmon found by xid.",
			})
		}
	}

	multiReply, _ := json.Marshal(replies)
	ctx.Data(http.StatusOK, "application/json", multiReply)
}
