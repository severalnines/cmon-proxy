package proxy

import (
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
