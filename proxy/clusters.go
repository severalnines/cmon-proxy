package proxy

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
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

// RPCClustersList constructs a high level reply of the cluster statuees
func (p *Proxy) RPCClustersList(ctx *gin.Context) {
	var req api.ClusterListRequest
	var resp api.ClusterListReply
	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp.Clusters = make([]*api.ClusterExt, 0, 32)
	resp.LastUpdated = make(map[string]*cmonapi.NullTime)

	p.r.GetAllClusterInfo(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.Clusters == nil {
			continue
		}
		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.Clusters.RequestCreated,
		}
		for _, cluster := range data.Clusters.Clusters {
			clus := &api.ClusterExt{
				WithControllerID: &api.WithControllerID{
					ControllerURL: url,
					ControllerID:  data.ControllerID(),
				},
				Cluster: cluster,
			}

			resp.Clusters = append(resp.Clusters, clus)
		}
	}

	ctx.JSON(http.StatusOK, &resp)
}
