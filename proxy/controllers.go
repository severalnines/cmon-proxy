package proxy

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/proxy/api"
)

func (router *Router) RPCControllerStatus(ctx *gin.Context) {
	retval := api.ControllerStatusList{
		Controllers: make([]*api.ControllerStatus, 0, len(router.PingResponses))}

	// this will ping the controllers
	router.Ping()

	// to keep version & ID information even when controller is down
	if controllerStatusCache == nil {
		controllerStatusCache = make(map[string]*api.ControllerStatus)
	}

	for addr, resp := range router.PingResponses {
		client := router.Clients[addr]

		// get it from cache
		status := controllerStatusCache[addr]
		if status == nil {
			status = &api.ControllerStatus{Url: addr}
		}

		status.Name = client.Instance.Name
		status.ControllerID = client.ControllerID()
		status.Status = api.Ok

		if router.PingErrors[addr] != nil {
			status.Status = api.Failed
			status.StatusMessage = router.PingErrors[addr].Error()

			// lets look if the root cause is auth related
			if client.RequestStatus() == cmonapi.RequestStatusAccessDenied ||
				client.RequestStatus() == cmonapi.RequestStatusAuthRequired {
				status.Status = api.AuthenticationError
			}
		}

		if resp != nil && len(resp.Version) > 0 {
			// prefer the version from the ping response
			status.Version = resp.Version
		} else if len(client.ServerVersion()) > 0 {
			// but we can go with the one from server header too
			status.Version = client.ServerVersion()
		}

		// persist in cache for later use
		controllerStatusCache[addr] = status

		retval.Controllers = append(retval.Controllers, status)
	}

	ctx.JSON(http.StatusOK, retval)
}

func (router *Router) pingOne(instance *config.CmonInstance) *api.ControllerStatus {
	client := cmon.NewClient(instance, router.Config.Timeout)
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

func (router *Router) RPCControllerTest(ctx *gin.Context) {
	var req api.AddControllerRequest
	var resp api.AddControllerResponse
	if err := ctx.BindJSON(&req); err != nil || req.Controller == nil {
		fmt.Println(req)
		ctx.JSON(http.StatusBadRequest,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	resp.Controller = router.pingOne(req.Controller)

	ctx.JSON(http.StatusOK, &resp)
}

func (router *Router) RPCControllerAdd(ctx *gin.Context) {
	var req api.AddControllerRequest
	var resp api.AddControllerResponse
	if err := ctx.BindJSON(&req); err != nil || req.Controller == nil {
		ctx.JSON(http.StatusBadRequest,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	resp.Controller = router.pingOne(req.Controller)

	for _, cmon := range router.Config.Instances {
		if cmon.Url == req.Controller.Url {
			ctx.JSON(http.StatusConflict, cmonapi.NewError(cmonapi.RequestStatusTryAgain, "Duplicate URL."))
			return
		}
	}

	router.Config.Instances = append(router.Config.Instances, req.Controller)
	if err := router.Config.Save(); err != nil {
		ctx.JSON(http.StatusInternalServerError,
			cmonapi.NewError(cmonapi.RequestStatusUnknownError,
				fmt.Sprintf("Controller addition failure: %s", err.Error())))
	}

	// also call authenticate, this will add the new client, it can be done delayed in a thread
	go func() {
		router.Authenticate()
	}()

	ctx.JSON(http.StatusOK, &resp)
}

func (router *Router) RPCControllerRemove(ctx *gin.Context) {
	var req api.RemoveControllerRequest
	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest,
			cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "Invalid request."))
		return
	}

	removeAt := -1
	for idx, cmon := range router.Config.Instances {
		if cmon.Url == req.Url {
			removeAt = idx
			break
		}
	}

	if removeAt < 0 {
		ctx.JSON(http.StatusNotFound,
			cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "Controller not found."))
		return
	}

	// remove & save
	router.Config.Instances[removeAt] = router.Config.Instances[len(router.Config.Instances)-1]
	router.Config.Instances = router.Config.Instances[:len(router.Config.Instances)-1]

	if err := router.Config.Save(); err != nil {
		ctx.JSON(http.StatusInternalServerError,
			cmonapi.NewError(cmonapi.RequestStatusUnknownError,
				fmt.Sprintf("Controller remove failure: %s", err.Error())))
		return
	}

	// also call authenticate, this will drop the existing client, it can be done delayed in a thread
	go func() {
		router.Authenticate()
	}()

	ctx.JSON(http.StatusOK, cmonapi.NewError(cmonapi.RequestStatusOk, "The controller is removed."))
}
