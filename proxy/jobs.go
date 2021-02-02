package proxy

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/proxy/api"
)

func (p *Proxy) RPCJobsStatus(ctx *gin.Context) {
	ctx.AbortWithError(http.StatusMethodNotAllowed, fmt.Errorf("Not implemented."))
}

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

	p.r.GetLastJobs(false)

	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.Jobs == nil {
			continue
		}
		if !api.PassFilter(req.Filters, "controller_id", data.ControllerID()) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.LastJobsRefresh,
		}
		for _, job := range data.Jobs {
			if !api.PassFilter(req.Filters, "cluster_id", strconv.FormatUint(job.ClusterID, 10)) {
				continue
			}
			if !api.PassFilterLazy(req.Filters, "cluster_type",
				func() string { return data.ClusterType(job.ClusterID) }) {
				continue
			}
			if !api.PassFilter(req.Filters, "job_command", job.JobSpec.Command) {
				continue
			}
			resp.Jobs = append(resp.Jobs,
				&api.JobExt{
					WithControllerID: &api.WithControllerID{
						ControllerID:  data.ControllerID(),
						ControllerURL: url,
					},
					Job: job,
				},
			)
		}
	}

	ctx.JSON(http.StatusOK, &resp)
}
