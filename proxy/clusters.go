package proxy

import (
	"github.com/gin-gonic/gin"
)

type ProxyClusterStatus struct {
	ClusterStates map[string]int `json:"cluster_states"`
	AlarmCounts   map[string]int `json:"alarm_counts"`
}

// RPCClustersStatus constructs a high level reply of the cluster statuees
func (p *Proxy) RPCClustersStatus(ctx *gin.Context) {
	/*
		logger := zap.L()

			for addr, client := range router.Clients {
				creq := &cmonapi.GetAllClusterInfoRequest{}
				cresp := &cmonapi.GetAllClusterInfoResponse{}

				if err := client.Request(cmonapi.ModuleClusters, creq, cresp, false); err != nil {
					logger.Sugar().Warnf("[cmon]", addr, "failure", err.Error())
					continue
				}
			}
	*/
}
