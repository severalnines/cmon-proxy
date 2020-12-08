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

	for addr, resp := range router.PingResponses {
		status := &api.ControllerStatus{Url: addr}
		status.Name = router.Clients[addr].Instance.Name

		status.Status = api.Ok
		if router.PingErrors[addr] != nil {
			status.Status = api.Failed
			status.StatusMessage = router.PingErrors[addr].Error()
		}
		if resp != nil {
			status.Version = resp.Version
		}

		retval.Controllers = append(retval.Controllers, status)
	}

	ctx.JSON(http.StatusOK, retval)
}
