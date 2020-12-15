package proxy

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/proxy/api"
)

// RPCClustersStatus constructs a high level reply of the cluster statuees
func (p *Proxy) RPCClustersStatus(ctx *gin.Context) {
	//logger := zap.L()

	resp := &api.ClustersOverview{
		ClusterStatus: make(map[string]int),
		ClustersCount: make(map[string]int),
		NodesCount:    make(map[string]int),
		NodeStates:    make(map[string]int),
	}

	p.r.GetAllClusterInfo(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.Clusters == nil {
			continue
		}
		for _, cluster := range data.Clusters.Clusters {
			resp.ClusterStatus[cluster.State]++
			resp.ClustersCount[url]++
			resp.NodesCount[url] += len(cluster.Hosts)
			for _, host := range cluster.Hosts {
				resp.NodeStates[host.HostStatus]++
			}
		}
	}

	ctx.JSON(http.StatusOK, resp)
}
