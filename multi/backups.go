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
	"github.com/severalnines/cmon-proxy/multi/router"
)

// RPCBackupsStatus returns the backup and backup schedule stats for each cluster
func (p *Proxy) RPCBackupsStatus(ctx *gin.Context) {
	var req api.SimpleFilteredRequest

	if ctx.Request.Method == http.MethodPost {
		if err := ctx.BindJSON(&req); err != nil {
			cmonapi.CtxWriteError(ctx,
				cmonapi.NewError(cmonapi.RequestStatusInvalidRequest,
					fmt.Sprint("Invalid request:", err.Error())))
			return
		}
	}

	resp := &api.BackupOverview{
		BackupCounts:             make(map[string]int),
		ByClusterType:            make(map[string]*api.BackupOverview),
		BackupCountsByController: make(map[string]*api.BackupOverview),
	}

	// refresh clusters and backups too
	p.Router(ctx).GetAllClusterInfo(false)
	p.Router(ctx).GetBackups(false)

	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil {
			continue
		}

		if resp.BackupCountsByController[url] == nil {
			resp.BackupCountsByController[url] = &api.BackupOverview{
				BackupCounts:  make(map[string]int),
				ByClusterType: make(map[string]*api.BackupOverview),
			}
		}

		// Resolve sources from pool controllers
		backupsSource, schedulesSource, _, _ := p.resolveBackupsSource(ctx, data)
		clustersSource, _, _ := p.resolveClustersSource(ctx, data)
		// Build metadata maps from clustersSource
		tagsByCID := make(map[uint64][]string)
		typeByCID := make(map[uint64]string)
		for _, cl := range clustersSource {
			if cl == nil {
				continue
			}
			tagsByCID[cl.ClusterID] = cl.Tags
			typeByCID[cl.ClusterID] = cl.ClusterType
		}

		for _, backup := range backupsSource {
			// tags filtration is possible here too
			var tags []string
			if t, ok := tagsByCID[backup.Metadata.ClusterID]; ok {
				tags = t
			} else {
				tags = data.ClusterTags(backup.Metadata.ClusterID)
			}
			fn := func() []string { return tags }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}
			clusterType := typeByCID[backup.Metadata.ClusterID]
			if clusterType == "" {
				clusterType = data.ClusterType(backup.Metadata.ClusterID)
			}

			if resp.ByClusterType[clusterType] == nil {
				resp.ByClusterType[clusterType] = &api.BackupOverview{
					BackupCounts:             make(map[string]int),
					BackupCountsByController: make(map[string]*api.BackupOverview),
				}
			}

			resp.BackupCounts[backup.Metadata.Status]++
			resp.ByClusterType[clusterType].BackupCounts[backup.Metadata.Status]++

			resp.BackupCountsByController[url].BackupCounts[backup.Metadata.Status]++

			if resp.BackupCountsByController[url].ByClusterType[clusterType] == nil {
				resp.BackupCountsByController[url].ByClusterType[clusterType] = &api.BackupOverview{
					BackupCounts:             make(map[string]int),
					BackupCountsByController: make(map[string]*api.BackupOverview),
				}
			}

			resp.BackupCountsByController[url].ByClusterType[clusterType].BackupCounts[backup.Metadata.Status]++
		}

		schedsPerCluster := make(map[string]map[uint64]int)
		// Derive cluster IDs from clustersSource to include pool-controller clusters
		for _, cl := range clustersSource {
			if cl == nil {
				continue
			}
			clusterType := cl.ClusterType
			if len(schedsPerCluster[clusterType]) == 0 {
				schedsPerCluster[clusterType] = make(map[uint64]int)
			}
			fn := func() []string { return cl.Tags }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}
			schedsPerCluster[clusterType][cl.ClusterID] = 0
		}
		for _, sched := range schedulesSource {
			clusterType := typeByCID[sched.ClusterID]
			if clusterType == "" {
				clusterType = data.ClusterType(sched.ClusterID)
			}
			// It can happen that clusterType is empty string @see data.ClusterType()
			if clusterType == "" {
				continue
			}
			var tags []string
			if t, ok := tagsByCID[sched.ClusterID]; ok {
				tags = t
			} else {
				tags = data.ClusterTags(sched.ClusterID)
			}
			fn := func() []string { return tags }
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}
			schedsPerCluster[clusterType][sched.ClusterID]++
		}

		for clusterType, clusters := range schedsPerCluster {
			if resp.ByClusterType[clusterType] == nil {
				resp.ByClusterType[clusterType] = &api.BackupOverview{
					BackupCounts:             make(map[string]int),
					BackupCountsByController: make(map[string]*api.BackupOverview),
				}
			}

			for _, schedules := range clusters {
				if schedules == 0 {
					resp.MissingSchedules++
					resp.ByClusterType[clusterType].MissingSchedules++
				}
				resp.SchedulesCount += schedules
				resp.ByClusterType[clusterType].SchedulesCount += schedules
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

	p.Router(ctx).GetBackups(req.ForceUpdate)
	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil {
			continue
		}

		controllerID := data.PoolID()
		xid := data.Xid()

		if !api.PassFilter(req.Filters, "xid", xid) ||
			!api.PassFilter(req.Filters, "controller_id", controllerID) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.LastUpdate[router.Backups],
		}

		backupsSource, _, _, _ := p.resolveBackupsSource(ctx, data)
		clustersSource, _, _ := p.resolveClustersSource(ctx, data)
		tagsByCID := make(map[uint64][]string)
		typeByCID := make(map[uint64]string)
		for _, cl := range clustersSource {
			if cl == nil {
				continue
			}
			tagsByCID[cl.ClusterID] = cl.Tags
			typeByCID[cl.ClusterID] = cl.ClusterType
		}

		for _, backup := range backupsSource {
			if !api.PassFilter(req.Filters, "xid_cid", xid+"-"+strconv.FormatUint(backup.Metadata.ClusterID, 10)) {
				continue
			}
			if !api.PassFilter(req.Filters, "backup_id", strconv.FormatUint(backup.Metadata.ID, 10)) {
				continue
			}
			if !api.PassFilter(req.Filters, "cluster_id", strconv.FormatUint(backup.Metadata.ClusterID, 10)) {
				continue
			}
			if !api.PassFilter(req.Filters, "status", backup.Metadata.Status) {
				continue
			}
			if !api.PassFilter(req.Filters, "method", backup.Metadata.Method) {
				continue
			}
			if !api.PassFilterLazy(req.Filters, "cluster_type",
				func() string {
					if v := typeByCID[backup.Metadata.ClusterID]; v != "" {
						return v
					}
					return data.ClusterType(backup.Metadata.ClusterID)
				}) {
				continue
			}
			fn := func() []string {
				if v, ok := tagsByCID[backup.Metadata.ClusterID]; ok {
					return v
				}
				return data.ClusterTags(backup.Metadata.ClusterID)
			}
			if !api.PassTagsFilterLazy(req.Filters, fn) {
				continue
			}

			b := &api.BackupExt{
				WithControllerID: &api.WithControllerID{
					ControllerURL: url,
					ControllerID:  controllerID,
					Xid:           xid,
				},
				Backup: backup,
				Key:    xid + "-" + strconv.FormatUint(backup.Metadata.ClusterID, 10),
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
			return resp.Backups[i].Metadata.ClusterID < resp.Backups[j].Metadata.ClusterID
		})
	case "status":
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].Metadata.Status < resp.Backups[j].Metadata.Status
		})
	case "method":
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].Metadata.Method < resp.Backups[j].Metadata.Method
		})
	case "id", "backup_id":
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].Metadata.ID < resp.Backups[j].Metadata.ID
		})
	case "created":

		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].Metadata.Created.T.Before(resp.Backups[j].Metadata.Created.T)
		})
	default:
		desc = true
		sort.Slice(resp.Backups[:], func(i, j int) bool {
			if desc {
				i, j = j, i
			}
			return resp.Backups[i].Metadata.Created.T.Before(resp.Backups[j].Metadata.Created.T)
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

	p.Router(ctx).GetBackups(req.ForceUpdate)

	for _, url := range p.Router(ctx).Urls() {
		data := p.Router(ctx).Cmon(url)
		if data == nil || data.BackupSchedules == nil {
			continue
		}

		xid := data.Xid()
		controllerID := data.PoolID()

		if !api.PassFilter(req.Filters, "xid", data.Xid()) ||
			!api.PassFilter(req.Filters, "controller_id", controllerID) ||
			!api.PassFilter(req.Filters, "controller_url", url) {
			continue
		}

		resp.LastUpdated[url] = &cmonapi.NullTime{
			T: data.LastUpdate[router.Jobs],
		}
		for _, job := range data.BackupSchedules {
			if !api.PassFilter(req.Filters, "xid_cid", xid+"-"+strconv.FormatUint(job.ClusterID, 10)) {
				continue
			}
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
