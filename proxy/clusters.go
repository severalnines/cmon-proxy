package proxy

import (
	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon/api"
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
		creq := &api.GetAllClusterInfoRequest{}
		cresp := &api.GetAllClusterInfoResponse{}

		if err := client.Request(api.ModuleClusters, creq, cresp, true); err != nil {
			logger.Sugar().Warnf("[cmon]", addr, "failure", err.Error())
			continue
		}

		/*
			if err := client.Request(cmon.ModuleClusters, creq, cresp, true); err != nil {
				logger.Sugar().Warnf("[cmon]", addr, "failure", err.Error())
				continue
			}
		*/
	}
}
