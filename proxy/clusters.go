package proxy

import (
	"fmt"
	"net/http"
	"sort"
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
		ByClusterType: make(map[string]*api.ClustersOverview),
	}

	p.r.GetAllClusterInfo(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.Clusters == nil {
			continue
		}
		for _, cluster := range data.Clusters.Clusters {
			if resp.ByClusterType[cluster.ClusterType] == nil {
				resp.ByClusterType[cluster.ClusterType] = &api.ClustersOverview{
					ClusterStatus: make(map[string]int),
					ClustersCount: make(map[string]int),
					NodesCount:    make(map[string]int),
					NodeStates:    make(map[string]int),
				}
			}

			resp.ClusterStatus[cluster.State]++
			resp.ByClusterType[cluster.ClusterType].ClusterStatus[cluster.State]++

			resp.ClustersCount[url]++
			resp.ByClusterType[cluster.ClusterType].ClustersCount[url]++

			resp.NodesCount[url] += len(cluster.Hosts) - 1
			resp.ByClusterType[cluster.ClusterType].NodesCount[url] += len(cluster.Hosts) - 1

			for _, host := range cluster.Hosts {
				if host.Nodetype == "controller" {
					continue
				}
				resp.NodeStates[host.HostStatus]++
				resp.ByClusterType[cluster.ClusterType].NodeStates[host.HostStatus]++
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
			fn := func() []string { return cluster.Tags }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
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

	// handle sorting && pagination
	resp.Page = req.Page
	resp.PerPage = req.PerPage
	resp.Total = uint64(len(resp.Clusters))
	// sort first
	order, desc := req.GetOrder()
	switch order {
	case "cluster_id":
		sort.Slice(resp.Clusters[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Clusters[i].ClusterID < resp.Clusters[j].ClusterID
		})
	case "state":
		sort.Slice(resp.Clusters[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Clusters[i].State < resp.Clusters[j].State
		})
	case "cluster_type":
		sort.Slice(resp.Clusters[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Clusters[i].ClusterType < resp.Clusters[j].ClusterType
		})
	}
	if req.ListRequest.PerPage > 0 {
		// then handle the pagination
		from, to := api.Paginate(req.ListRequest, int(resp.Total))
		resp.Clusters = resp.Clusters[from:to]
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
			fn := func() []string { return cluster.Tags }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
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

	// handle sorting && pagination
	resp.Page = req.Page
	resp.PerPage = req.PerPage
	resp.Total = uint64(len(resp.Hosts))
	// sort first
	order, desc := req.GetOrder()
	switch order {
	case "cluster_id":
		sort.Slice(resp.Hosts[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Hosts[i].ClusterID < resp.Hosts[j].ClusterID
		})
	case "port":
		sort.Slice(resp.Hosts[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Hosts[i].Port < resp.Hosts[j].Port
		})
	case "hostname":
		sort.Slice(resp.Hosts[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Hosts[i].Hostname < resp.Hosts[j].Hostname
		})
	case "role":
		sort.Slice(resp.Hosts[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Hosts[i].Role < resp.Hosts[j].Role
		})
	case "nodetype":
		sort.Slice(resp.Hosts[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Hosts[i].Nodetype < resp.Hosts[j].Nodetype
		})
	case "hoststatus":
		sort.Slice(resp.Hosts[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Hosts[i].HostStatus < resp.Hosts[j].HostStatus
		})
	}
	if req.ListRequest.PerPage > 0 {
		// then handle the pagination
		from, to := api.Paginate(req.ListRequest, int(resp.Total))
		resp.Hosts = resp.Hosts[from:to]
	}

	ctx.JSON(http.StatusOK, &resp)
}
