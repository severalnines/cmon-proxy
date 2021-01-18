package proxy

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/proxy/api"
)

// RPCJobsList gives back a list of clusters
func (p *Proxy) RPCJobsList(ctx *gin.Context) {
	var req api.JobListRequest
	var resp api.JobListReply
	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}
	// by defaults lets go with 12 hours
	if req.LastNHours <= 1 {
		req.LastNHours = 12
	}

	resp.Jobs = make([]*api.JobExt, 0, 32)
	resp.LastUpdated = make(map[string]*cmonapi.NullTime)

	/*
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
				if !api.PassFilterLazy(req.Filters, "cluster_type",
					func() string { return data.ClusterType(cid) }) {
					continue
				}
				resp.Jobs = append(resp.Jobs, job)
			}
		}
	*/
	ctx.JSON(http.StatusOK, &resp)
}
