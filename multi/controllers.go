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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi/api"
	"github.com/severalnines/cmon-proxy/multi/router"
)

const maxControllerNameLength = 60

func truncateControllerName(name string) string {
	if len(name) > maxControllerNameLength {
		return name[:maxControllerNameLength]
	}
	return name
}

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

	if forceLicenseCheck || req.ForceUpdate {
		// make sure license info is re-freshed
		p.Router(ctx).GetAllClusterInfo(req.ForceUpdate)
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
				Url: addr,
			}
		}

		status.Name = truncateControllerName(c.Client.Instance.Name)
		status.ControllerID = c.ControllerID()
		status.Xid = c.Xid()
		status.Status = api.Ok
		status.Ldap = c.Client.Instance.UseLdap
		status.UseCmonAuth = c.Client.Instance.UseCmonAuth
		status.FrontendUrl = c.Client.Instance.FrontendUrl
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
		Name:         truncateControllerName(instance.Name),
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

	// Get current in-memory credentials
	auth := p.Router(ctx).AuthController
	if auth.Use {
		if req.Controller.Xid != "" {
			// which means it is editing existing controller
			// @TODO: check how LDAP works with this
			req.Controller.Username = auth.Username
			req.Controller.Password = auth.Password
		}
		// Use these credentials for a new controller
		req.Controller.UseCmonAuth = false
		// Now you can authenticate this instance
		client := cmon.NewClient(req.Controller, p.Router(ctx).Config.Timeout)
		err := client.Authenticate()
		if err != nil {
			resp.Controller = p.pingOne(req.Controller)
			resp.Controller.StatusMessage = err.Error()
			resp.Controller.Status = api.Failed
		}
	}

	resp.Controller = p.pingOne(req.Controller)

	ctx.JSON(http.StatusOK, &resp)
}

func (p *Proxy) RPCControllerAdd(ctx *gin.Context) {
	var req api.AddControllerRequest
	var resp api.AddControllerResponse

	session := sessions.Default(ctx)
	elevated := session.Get("elevated") == true
	if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
		if !authenticatedUser.Admin && !elevated {
			cmonapi.CtxWriteError(ctx, fmt.Errorf("Only admin users can add controllers"), http.StatusForbidden)
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

	session := sessions.Default(ctx)
	elevated := session.Get("elevated") == true
	if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
		if !authenticatedUser.Admin && !elevated {
			cmonapi.CtxWriteError(ctx, fmt.Errorf("only admin users can update controllers"), http.StatusForbidden)
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

	c, err := p.GetCmonById(req.Controller.Xid, nil)
	if err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	// remove & add it again
	if err := p.Router(nil).Config.RemoveController(req.Controller.Xid, false); err != nil {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "Controller not found ("+err.Error()+")"))
		return
	}
	if err := p.Router(nil).Config.AddController(req.Controller, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	c.InvalidateCache()
	c.Client.ResetSession()

	resp.Controller = p.pingOne(req.Controller)

	// it is going to refresh everything
	p.Refresh()

	ctx.JSON(http.StatusOK, &resp)
}

func (p *Proxy) RPCControllerRemove(ctx *gin.Context) {
	var req api.RemoveControllerRequest

	session := sessions.Default(ctx)
	elevated := session.Get("elevated") == true
	if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
		if !authenticatedUser.Admin && !elevated {
			cmonapi.CtxWriteError(ctx, fmt.Errorf("only admin users can remove controllers"), http.StatusForbidden)
			return
		}
	}

	if err := ctx.BindJSON(&req); err != nil || len(req.ControllerXid) < 1 {
		cmonapi.CtxWriteError(ctx,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	if err := p.Router(nil).Config.RemoveController(req.ControllerXid, true); err != nil {
		cmonapi.CtxWriteError(ctx, err)
		return
	}

	// it is going to refresh everything
	p.Refresh()

	ctx.JSON(http.StatusOK, cmonapi.NewError(cmonapi.RequestStatusOk, "The controller is removed."))
}

func (p *Proxy) GetCmonById(controllerId string, ctx *gin.Context) (*router.Cmon, error) {
	instance := p.Router(ctx).Config.ControllerById(controllerId)
	if instance == nil {
		return nil, cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "Controller not found")

	}
	c := p.Router(ctx).Cmon(instance.Url)
	if c == nil {
		return nil, cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "CMON object not found")
	}

	return c, nil
}

func (p *Proxy) CmonShhHttpProxyRequest(ctx *gin.Context) {
	xid := ctx.Param("xid")

	c, err := p.GetCmonById(xid, ctx)
	if err != nil {
		http.Error(ctx.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	scheme := "http"
	host := c.Client.Instance.CMONSshHost
	if host == "" {
		host = c.Client.Instance.Url + "/v2/cmon-ssh"
		scheme = "https"
	}
	if c.Client.Instance.CMONSshSecure {
		scheme = "https"
	}
	target := scheme + "://" + host + ctx.Param("any")

	proxy, err := c.Client.GetReverseProxy(target)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error parsing target URL"})
		return
	}
	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

var upGrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (p *Proxy) CmonShhWsProxyRequest(ctx *gin.Context) {
	xid := ctx.Param("xid")

	c, err := p.GetCmonById(xid, ctx)
	if err != nil {
		http.Error(ctx.Writer, err.Error(), http.StatusBadRequest)
		return
	}

	conn, err := upGrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		http.Error(ctx.Writer, "Could not open websocket connection", http.StatusBadRequest)
		return
	}
	// If ProxyWebSocket succeeds, it takes ownership of conn. If it fails, or we panic,
	// this defer ensures the client connection is closed.
	clientConnectionClosed := false
	defer func() {
		if !clientConnectionClosed {
			log.Println("CmonShhWsProxyRequest: Ensuring client-side WebSocket connection is closed due to error or early exit.")
			conn.Close()
		}
	}()

	scheme := "ws"
	host := c.Client.Instance.CMONSshHost
	if host == "" {
		host = c.Client.Instance.Url + "/v2/cmon-ssh/"
		scheme = "wss"
	}
	if c.Client.Instance.CMONSshSecure {
		scheme = "wss"
	}
	postfix := ctx.Param("any")
	targetURL := scheme + "://" + host + postfix

	err = c.Client.ProxyWebSocket(targetURL, http.Header{
		"Origin": {ctx.Request.Header.Get("Origin")},
	}, conn)
	if err != nil {
		http.Error(ctx.Writer, "Could not connect to target websocket", http.StatusInternalServerError)
		return
	}

	// If ProxyWebSocket returned successfully, it now owns the connection.
	// Mark clientConnectionClosed as true so the defer func doesn't close it.
	clientConnectionClosed = true
}

func (p *Proxy) RPCProxyRequest(ctx *gin.Context, controllerId, method string, reqBytes []byte) {
	var err error
	// do we need this here? it could do (re-)auth and things like that
	// p.r.Ping()

	//authenticatedUserName := "<anonymous>"
	//if authenticatedUser := getUserForSession(ctx); authenticatedUser != nil {
	//	authenticatedUserName = authenticatedUser.Username
	//}

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

	// change URL to the cmon RPC one
	requestUrlFixed := strings.Replace(ctx.Request.URL.EscapedPath(), "/v2multi/", "/v2/", 1)

	for _, addr := range p.Router(ctx).Urls() {
		c := p.Router(ctx).Cmon(addr)
		if c == nil || c.Client == nil {
			continue
		}

		if len(xIds) > 0 {
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
			resBytes, err = c.Client.RequestBytes(requestUrlFixed, reqBytes, false)
			if err != nil {
				var resp cmonapi.WithResponseData
				if err != nil {
					resp.RequestStatus = cmonapi.RequestStatusUnknownError
					resp.ErrorString = "error while communicating to cmon:" + err.Error()
				}
				repliesMtx.Lock()
				replies[c.Xid()], err = json.Marshal(resp)
				repliesMtx.Unlock()

				return

			} else if err = json.Unmarshal(resBytes, &parsed); err != nil || len(parsed) < 1 {
				replyData := make(map[string]interface{})
				replyData["xid"] = c.Xid()
				replyData["data"] = resBytes // this isn't JSon just some RAW reply

				repliesMtx.Lock()
				replies[c.Xid()], err = json.Marshal(replyData)
				repliesMtx.Unlock()

				return
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

/**
 * This is a special case where we are proxying the request to a single controller
 * No authentication is required, requests are proxied directly to the controller
 */
func (p *Proxy) PRCProxySingleController(ctx *gin.Context) {
	resp := &cmonapi.WithResponseData{
		RequestProcessed: cmonapi.NullTime{T: time.Now()},
		RequestStatus:    cmonapi.RequestStatusOk,
		ErrorString:      "",
	}

	if p.cfg.SingleController == "" {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Single controller is not defined"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}
	controller := p.cfg.ControllerById(p.cfg.SingleController)
	targetURL, _ := url.Parse("https://" + controller.Url + "/v2" + ctx.Param("any"))

	var body *bytes.Reader
	if ctx.Request.Body != nil {
		bodyBytes, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			resp.RequestStatus = cmonapi.RequestStatusUnknownError
			resp.ErrorString = "Failed to read request body"
			ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
			return
		}
		body = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(ctx.Request.Method, targetURL.String(), body)
	if err != nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Failed to create request"
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}
	for key, values := range ctx.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	response, err := client.Do(req)
	if err != nil {
		resp.RequestStatus = cmonapi.RequestStatusUnknownError
		resp.ErrorString = "Failed to forward request" + targetURL.String() + err.Error()
		ctx.JSON(cmonapi.RequestStatusToStatusCode(resp.RequestStatus), resp)
		return
	}

	defer func(b io.ReadCloser) {
		if b == nil {
			return
		}
		_ = b.Close()
	}(response.Body)
	cookies := response.Cookies()
	for _, cookie := range cookies {
		cookie.Path = "/"
		http.SetCookie(ctx.Writer, cookie)
	}
	for key, values := range response.Header {
		if strings.EqualFold(key, "Set-Cookie") {
			continue
		}
		for _, value := range values {
			ctx.Writer.Header().Add(key, value)
		}
	}

	ctx.Status(response.StatusCode)
	if response.Body != nil {
		_, _ = io.Copy(ctx.Writer, response.Body)
	}
}

/**
 * Single controller websocket proxy without authentication
 * This works like PRCProxySingleController but for websocket connections
 */
func (p *Proxy) PRCProxySingleControllerWebSocket(ctx *gin.Context) {
	if p.cfg.SingleController == "" {
		http.Error(ctx.Writer, "Single controller is not defined", http.StatusBadRequest)
		return
	}

	controller := p.cfg.ControllerById(p.cfg.SingleController)
	if controller == nil {
		http.Error(ctx.Writer, "Controller not found", http.StatusBadRequest)
		return
	}

	// Upgrade connection to websocket
	conn, err := upGrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		log.Printf("PRCProxySingleControllerWebSocket: Failed to upgrade to websocket: %v\n", err)
		return
	}

	clientConnectionClosed := false
	defer func() {
		if !clientConnectionClosed {
			log.Println("PRCProxySingleControllerWebSocket: Ensuring client-side WebSocket connection is closed due to error or early exit.")
			conn.Close()
		}
	}()

	// Construct target websocket URL - matching original logic
	scheme := "ws"
	host := controller.CMONSshHost
	if host == "" {
		host = controller.Url + "/v2/cmon-ssh/"
		scheme = "wss"
	}
	if controller.CMONSshSecure {
		scheme = "wss"
	}
	postfix := ctx.Param("any")
	targetURL := scheme + "://" + host + postfix

	log.Printf("PRCProxySingleControllerWebSocket: Constructed target WebSocket URL: %s\n", targetURL)

	// Create websocket dialer with TLS config
	dialer := websocket.Dialer{}

	// Copy headers from original request
	headers := http.Header{}
	for key, values := range ctx.Request.Header {
		// Skip websocket-specific headers that the dialer will add automatically
		lowerKey := strings.ToLower(key)
		if lowerKey == "sec-websocket-version" ||
			lowerKey == "sec-websocket-key" ||
			lowerKey == "sec-websocket-extensions" ||
			lowerKey == "sec-websocket-protocol" ||
			lowerKey == "connection" ||
			lowerKey == "upgrade" {
			continue
		}
		for _, value := range values {
			headers.Add(key, value)
		}
	}
	headers.Set("Origin", ctx.Request.Header.Get("Origin"))

	// Connect to target websocket without authentication
	targetConn, _, err := dialer.Dial(targetURL, headers)
	if err != nil {
		log.Printf("PRCProxySingleControllerWebSocket: Error connecting to target %s: %v\n", targetURL, err)
		return
	}
	defer targetConn.Close()

	// Handle message proxying in both directions
	go func() {
		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				return
			}
			err = targetConn.WriteMessage(messageType, p)
			if err != nil {
				return
			}
		}
	}()

	for {
		messageType, p, err := targetConn.ReadMessage()
		if err != nil {
			log.Printf("PRCProxySingleControllerWebSocket: Error reading message from target: %v\n", err)
			return
		}
		err = conn.WriteMessage(messageType, p)
		if err != nil {
			log.Printf("PRCProxySingleControllerWebSocket: Error writing message to client: %v\n", err)
			return
		}
	}
}

/**
 * Single controller HTTP proxy without authentication
 * This works like PRCProxySingleController but specifically for HTTP requests to cmon-ssh
 */
func (p *Proxy) PRCProxySingleControllerHttp(ctx *gin.Context) {
	if p.cfg.SingleController == "" {
		http.Error(ctx.Writer, "Single controller is not defined", http.StatusBadRequest)
		return
	}

	controller := p.cfg.ControllerById(p.cfg.SingleController)
	if controller == nil {
		http.Error(ctx.Writer, "Controller not found", http.StatusBadRequest)
		return
	}

	// Construct target URL - matching original logic
	scheme := "http"
	host := controller.CMONSshHost
	if host == "" {
		host = controller.Url + "/v2/cmon-ssh"
		scheme = "https"
	}
	if controller.CMONSshSecure {
		scheme = "https"
	}
	targetURL := scheme + "://" + host + ctx.Param("any")

	// Create HTTP request
	var body io.Reader
	if ctx.Request.Body != nil {
		bodyBytes, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			http.Error(ctx.Writer, "Failed to read request body", http.StatusBadRequest)
			return
		}
		body = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(ctx.Request.Method, targetURL, body)
	if err != nil {
		http.Error(ctx.Writer, "Failed to create request", http.StatusBadRequest)
		return
	}

	// Copy headers from original request
	for key, values := range ctx.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Create HTTP client with TLS config
	tr := &http.Transport{}
	client := &http.Client{Transport: tr}

	// Execute request
	response, err := client.Do(req)
	if err != nil {
		http.Error(ctx.Writer, "Failed to forward request: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	// Copy response headers
	for key, values := range response.Header {
		for _, value := range values {
			ctx.Writer.Header().Add(key, value)
		}
	}

	// Copy cookies
	cookies := response.Cookies()
	for _, cookie := range cookies {
		cookie.Path = "/"
		http.SetCookie(ctx.Writer, cookie)
	}

	// Copy status and body
	ctx.Status(response.StatusCode)
	if response.Body != nil {
		_, _ = io.Copy(ctx.Writer, response.Body)
	}
}
