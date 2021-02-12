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

// RPCBackupsStatus returns the backup and backup schedule stats for each cluster
func (p *Proxy) RPCBackupsStatus(ctx *gin.Context) {
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
func (p *Proxy) RPCBackupsList(ctx *gin.Context) {
	var req api.BackupListRequest
	var resp api.BackupListReply

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp.Backups = make([]*api.BackupExt, 0, 32)
	resp.LastUpdated = make(map[string]*cmonapi.NullTime)

	p.r.GetBackups(false)
	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.Backups == nil {
			continue
		}
		if !api.PassFilter(req.Filters, "controller_id", data.ControllerID()) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.LastBackupsRefresh,
		}
		for idx, backup := range data.Backups {
			if !api.PassFilter(req.Filters, "backup_id", strconv.FormatUint(backup.ID, 10)) {
				continue
			}
			if !api.PassFilter(req.Filters, "cluster_id", strconv.FormatUint(backup.ClusterID, 10)) {
				continue
			}
			if !api.PassFilter(req.Filters, "status", backup.Status) {
				continue
			}
			if !api.PassFilter(req.Filters, "method", backup.Method) {
				continue
			}
			if !api.PassFilterLazy(req.Filters, "cluster_type",
				func() string { return data.ClusterType(backup.ClusterID) }) {
				continue
			}
			fn := func() []string { return data.ClusterTags(backup.ClusterID) }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}

			b := &api.BackupExt{
				WithControllerID: &api.WithControllerID{
					ControllerURL: url,
					ControllerID:  data.ControllerID(),
				},
				Backup: data.Backups[idx],
			}

			resp.Backups = append(resp.Backups, b)
		}
	}

	// handle sorting && pagination
	resp.Page = req.Page
	resp.PerPage = req.PerPage
	resp.Total = uint64(len(resp.Backups))
	// sort first
	order, desc := req.GetOrder()
	switch order {
	case "cluster_id":
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].ClusterID < resp.Backups[j].ClusterID
		})
	case "status":
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].Status < resp.Backups[j].Status
		})
	case "method":
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].Method < resp.Backups[j].Method
		})
	case "id", "backup_id":
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].ID < resp.Backups[j].ID
		})
	}

	if req.ListRequest.PerPage > 0 {
		// then handle the pagination
		from, to := api.Paginate(req.ListRequest, int(resp.Total))
		resp.Backups = resp.Backups[from:to]
	}

	ctx.JSON(http.StatusOK, &resp)
}

// RPCBackupJobsList gives back a list of scheduled backup jobs
func (p *Proxy) RPCBackupJobsList(ctx *gin.Context) {
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

	p.r.GetBackups(false)

	for _, url := range p.r.Urls() {
		data := p.r.Cmon(url)
		if data == nil || data.BackupSchedules == nil {
			continue
		}
		if !api.PassFilter(req.Filters, "controller_id", data.ControllerID()) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.LastJobsRefresh,
		}
		for _, job := range data.BackupSchedules {
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
			if !api.PassFilter(req.Filters, "status", job.Status) {
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
