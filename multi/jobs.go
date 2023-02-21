package multi

// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/multi/api"
)

func (p *Proxy) RPCJobsStatus(ctx *gin.Context) {
	var req api.SimpleFilteredRequest

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest,
					fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp := &api.JobsStatus{
		JobCounts:             make(map[string]int),
		JobCommands:           make(map[string]int),
		JobCountsByController: make(map[string]*api.JobsStatus),
		ByClusterType:         make(map[string]*api.JobsStatus),
	}

	p.Router(ctx).GetLastJobs(false)
	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil || data.Clusters == nil {
			continue
		}

		countsByCtrl := &api.JobsStatus{
			JobCounts:   make(map[string]int),
			JobCommands: make(map[string]int),
		}
		// iterate by clusterIds... one by one..
		for _, job := range data.Jobs {
			// tags filtration is possible here too
			fn := func() []string { return data.ClusterTags(job.ClusterID) }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}

			clusterType := data.ClusterType(job.ClusterID)
			if stat, found := resp.ByClusterType[clusterType]; !found || stat == nil {
				resp.ByClusterType[clusterType] =
					&api.JobsStatus{
						JobCounts:             make(map[string]int),
						JobCommands:           make(map[string]int),
						JobCountsByController: make(map[string]*api.JobsStatus),
					}
			}

			if jbc, found := resp.ByClusterType[clusterType].JobCountsByController[url]; !found || jbc == nil {
				resp.ByClusterType[clusterType].JobCountsByController[url] =
					&api.JobsStatus{
						JobCounts:   make(map[string]int),
						JobCommands: make(map[string]int),
					}
			}

			resp.JobCounts[job.Status]++
			resp.JobCommands[job.Command()]++

			resp.ByClusterType[clusterType].JobCounts[job.Status]++
			resp.ByClusterType[clusterType].JobCommands[job.Command()]++

			countsByCtrl.JobCounts[job.Status]++
			countsByCtrl.JobCommands[job.Command()]++

			resp.ByClusterType[clusterType].JobCountsByController[url].JobCounts[job.Status]++
			resp.ByClusterType[clusterType].JobCountsByController[url].JobCommands[job.Command()]++
		}

		resp.JobCountsByController[url] = countsByCtrl
	}

	ctx.JSON(http.StatusOK, resp)
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

	resp.Jobs = make([]*api.JobExt, 0, 32)
	resp.LastUpdated = make(map[string]*cmonapi.NullTime)

	p.Router(ctx).GetLastJobs(false)

	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil || data.Jobs == nil {
			continue
		}

		controllerID := data.ControllerID()
		xid := data.Xid()

		if !api.PassFilter(req.Filters, "xid", xid) ||
			!api.PassFilter(req.Filters, "controller_id", controllerID) ||
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
			if !api.PassFilter(req.Filters, "job_id", strconv.FormatUint(job.JobID, 10)) {
				continue
			}
			if !api.PassFilterLazy(req.Filters, "cluster_type",
				func() string { return data.ClusterType(job.ClusterID) }) {
				continue
			}
			fn := func() []string { return data.ClusterTags(job.ClusterID) }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}
			if !api.PassFilter(req.Filters, "job_command", job.Command()) {
				continue
			}
			if !api.PassFilter(req.Filters, "status", job.Status) {
				continue
			}
			resp.Jobs = append(resp.Jobs,
				&api.JobExt{
					WithControllerID: &api.WithControllerID{
						ControllerID:  controllerID,
						ControllerURL: url,
						Xid:           xid,
					},
					Job: job,
				},
			)
		}
	}

	// handle sorting && pagination
	resp.Page = req.Page
	resp.PerPage = req.PerPage
	resp.Total = uint64(len(resp.Jobs))
	// sort first
	order, desc := req.GetOrder()
	switch order {
	case "cluster_id":
		sort.Slice(resp.Jobs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Jobs[i].ClusterID < resp.Jobs[j].ClusterID
		})
	case "job_command":
		sort.Slice(resp.Jobs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Jobs[i].Command() < resp.Jobs[j].Command()
		})
	case "job_id":
		sort.Slice(resp.Jobs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Jobs[i].JobID < resp.Jobs[j].JobID
		})
	case "status":
		sort.Slice(resp.Jobs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Jobs[i].Status < resp.Jobs[j].Status
		})
	case "title":
		sort.Slice(resp.Jobs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Jobs[i].Title < resp.Jobs[j].Title
		})
	case "created":
		sort.Slice(resp.Jobs[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Jobs[i].Created.T.Before(resp.Jobs[j].Created.T)
		})
	}
	if req.ListRequest.PerPage > 0 {
		// then handle the pagination
		from, to := api.Paginate(req.ListRequest, int(resp.Total))
		resp.Jobs = resp.Jobs[from:to]
	}

	ctx.JSON(http.StatusOK, &resp)
}
