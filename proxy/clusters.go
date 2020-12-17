package proxy

import (
	"fmt"
	"net/http"
	"strconv"

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
			resp.NodesCount[url] += len(cluster.Hosts) - 1
			for _, host := range cluster.Hosts {
				if host.Nodetype == "controller" {
					continue
				}
				resp.NodeStates[host.HostStatus]++
			}
		}
	}

	ctx.JSON(http.StatusOK, resp)
}

// RPCClustersList gives back a list of clusters
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
		if !api.PassFilter(req.Filters, "controller_id", data.ControllerID()) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.Clusters.RequestProcessed,
		}
		for _, cluster := range data.Clusters.Clusters {
			if !api.PassFilter(req.Filters, "cluster_id", strconv.FormatUint(cluster.ClusterID, 10)) {
				continue
			}
			if !api.PassFilter(req.Filters, "state", cluster.State) {
				continue
			}
			if !api.PassFilter(req.Filters, "cluster_type", cluster.ClusterType) {
				continue
			}

			clus := &api.ClusterExt{
				WithControllerID: &api.WithControllerID{
					ControllerURL: url,
					ControllerID:  data.ControllerID(),
				},
				Cluster: cluster.Copy(req.WithHosts, true),
			}

			resp.Clusters = append(resp.Clusters, clus)
		}
	}

	ctx.JSON(http.StatusOK, &resp)
}

// RPCClustersNodesList gives back a list of nodes
func (p *Proxy) RPCClustersHostList(ctx *gin.Context) {
	var req api.HostListRequest
	var resp api.HostListReply
	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp.Hosts = make([]*api.HostExt, 0, 128)
	resp.LastUpdated = make(map[string]*cmonapi.NullTime)

	p.r.GetAllClusterInfo(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.Clusters == nil {
			continue
		}
		if !api.PassFilter(req.Filters, "controller_id", data.ControllerID()) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.Clusters.RequestProcessed,
		}
		for _, cluster := range data.Clusters.Clusters {
			// yeah host instances have 'clusterid' instead of 'cluster_id' :-S
			if !api.PassFilter(req.Filters, "cluster_id", strconv.FormatUint(cluster.ClusterID, 10)) ||
				!api.PassFilter(req.Filters, "clusterid", strconv.FormatUint(cluster.ClusterID, 10)) {
				continue
			}
			if !api.PassFilter(req.Filters, "cluster_type", cluster.ClusterType) {
				continue
			}

			for _, host := range cluster.Hosts {
				// skip controller hosts
				if host.Nodetype == "controller" {
					continue
				}

				if !api.PassFilter(req.Filters, "port", strconv.FormatInt(int64(host.Port), 10)) {
					continue
				}
				if !api.PassFilter(req.Filters, "hostname", host.Hostname) {
					continue
				}
				if !api.PassFilter(req.Filters, "role", host.Role) {
					continue
				}
				if !api.PassFilter(req.Filters, "nodetype", host.Nodetype) {
					continue
				}
				if !api.PassFilter(req.Filters, "hoststatus", host.HostStatus) {
					continue
				}

				h := &api.HostExt{
					WithControllerID: &api.WithControllerID{
						ControllerURL: url,
						ControllerID:  data.ControllerID(),
					},
					Host: host,
				}
				resp.Hosts = append(resp.Hosts, h)
			}
		}
	}

	ctx.JSON(http.StatusOK, &resp)
}
