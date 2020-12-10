package proxy

import (
	"net/http"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/proxy/api"
	"go.uber.org/zap"
)

type ProxyClusterStatus struct {
	ClusterStates map[string]int `json:"cluster_states"`
	AlarmCounts   map[string]int `json:"alarm_counts"`
}

var (
	controllerStatusCache map[string]*api.ControllerStatus
)

// RPCClustersStatus constructs a high level reply of the cluster statuees
func (router *Router) RPCClustersStatus(ctx *gin.Context) {
	logger := zap.L()

	for addr, client := range router.Clients {
		creq := &cmonapi.GetAllClusterInfoRequest{}
		cresp := &cmonapi.GetAllClusterInfoResponse{}

		if err := client.Request(cmonapi.ModuleClusters, creq, cresp, false); err != nil {
			logger.Sugar().Warnf("[cmon]", addr, "failure", err.Error())
			continue
		}

		/*
			if err := client.Request(cmon.ModuleClusters, creq, cresp, false); err != nil {
				logger.Sugar().Warnf("[cmon]", addr, "failure", err.Error())
				continue
			}
		*/
	}
}

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
