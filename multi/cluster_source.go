package multi

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/multi/router"
)

// resolveClustersSource returns the preferred cluster list for a controller:
// - If pool-controllers are cached, it queries each hostname:(port+1) and aggregates results
// - Otherwise, it falls back to the main controller cached clusters
// It also returns controllerID and xid for convenience.
func (p *Proxy) resolveClustersSource(ctx *gin.Context, data *router.Cmon) ([]*cmonapi.Cluster, string, string) {
	if data == nil {
		return nil, "", ""
	}
	controllerID := data.PoolID()
	xid := data.Xid()

	// Use cached pool controllers (status or instance-configured)
	pcs := p.GetCachedPoolControllers(ctx, controllerID)
	if len(pcs) == 0 {
		pcs = p.GetCachedPoolControllers(ctx, xid)
	}
	clusters := make([]*cmonapi.Cluster, 0)

	if len(pcs) > 0 && data.Client != nil {
		seen := make(map[uint64]bool)
		for _, pc := range pcs {
			if pc == nil || len(pc.Hostname) == 0 || pc.Port == 0 {
				continue
			}
			// Only target active pool controllers if status is provided
			if len(pc.Status) > 0 && !strings.EqualFold(pc.Status, "active") {
				continue
			}
			inst := data.Client.Instance.Copy()
			inst.Url = fmt.Sprintf("%s:%d", pc.Hostname, pc.Port+1)
			pcClient := cmon.NewClient(inst, p.Router(ctx).Config.Timeout)
			if sess := data.Client.GetSessionCookie(); sess != nil {
				pcClient.SetSessionCookie(sess)
			}
			listResp, err := pcClient.GetAllClusterInfo(&cmonapi.GetAllClusterInfoRequest{
				WithOperation:    &cmonapi.WithOperation{Operation: "getAllClusterInfo"},
				WithSheetInfo:    false,
				WithDatabases:    false,
				WithLicenseCheck: true,
				WithHosts:        true,
				WithTags:         true,
			})
			if err != nil || listResp == nil || listResp.Clusters == nil {
				continue
			}
			for _, cl := range listResp.Clusters {
				if cl == nil || seen[cl.ClusterID] {
					continue
				}
				seen[cl.ClusterID] = true
				clusters = append(clusters, cl)
			}
		}
	}

	// Fallback to main controller cache
	if len(clusters) == 0 && data.Clusters != nil && data.Clusters.Clusters != nil {
		return data.Clusters.Clusters, controllerID, xid
	}
	return clusters, controllerID, xid
}

// resolveBackupsSource returns backups and backup schedules gathered from pool controllers
// when available (querying hostname:(port+1)), otherwise falls back to the main controller
// cached data. Also returns controllerID and xid.
func (p *Proxy) resolveBackupsSource(ctx *gin.Context, data *router.Cmon) ([]*cmonapi.Backup, []*cmonapi.Job, string, string) {
	if data == nil {
		return nil, nil, "", ""
	}
	controllerID := data.PoolID()
	xid := data.Xid()

	pcs := p.GetCachedPoolControllers(ctx, controllerID)
	if len(pcs) == 0 {
		pcs = p.GetCachedPoolControllers(ctx, xid)
	}

	backups := make([]*cmonapi.Backup, 0)
	schedules := make([]*cmonapi.Job, 0)

	if len(pcs) > 0 && data.Client != nil {
		// number of days to fetch backups from
		fetchBackupDays := p.Router(ctx).Config.FetchBackupDays
		if fetchBackupDays < 1 {
			fetchBackupDays = 7
		}

		seenBackupID := make(map[uint64]bool)
		seenJobID := make(map[uint64]bool)

		for _, pc := range pcs {
			if pc == nil || len(pc.Hostname) == 0 || pc.Port == 0 {
				continue
			}
			if len(pc.Status) > 0 && !strings.EqualFold(pc.Status, "active") {
				continue
			}
			inst := data.Client.Instance.Copy()
			inst.Url = fmt.Sprintf("%s:%d", pc.Hostname, pc.Port+1)
			pcClient := cmon.NewClient(inst, p.Router(ctx).Config.Timeout)
			if sess := data.Client.GetSessionCookie(); sess != nil {
				pcClient.SetSessionCookie(sess)
			}

			if list, _ := pcClient.GetLastBackups(nil, fetchBackupDays); list != nil {
				for _, b := range list {
					if b == nil || seenBackupID[b.Metadata.ID] {
						continue
					}
					seenBackupID[b.Metadata.ID] = true
					backups = append(backups, b)
				}
			}
			if jobs, _ := pcClient.GetBackupJobs(nil); jobs != nil {
				for _, j := range jobs {
					if j == nil || seenJobID[j.JobID] {
						continue
					}
					seenJobID[j.JobID] = true
					schedules = append(schedules, j)
				}
			}
		}
	}

	if len(backups) == 0 && len(schedules) == 0 {
		return data.Backups, data.BackupSchedules, controllerID, xid
	}
	return backups, schedules, controllerID, xid
}

// resolveJobsSource returns jobs gathered from pool controllers when available
// (querying hostname:(port+1)), otherwise falls back to the main controller cached jobs.
func (p *Proxy) resolveJobsSource(ctx *gin.Context, data *router.Cmon) ([]*cmonapi.Job, string, string) {
	if data == nil {
		return nil, "", ""
	}
	controllerID := data.PoolID()
	xid := data.Xid()

	pcs := p.GetCachedPoolControllers(ctx, controllerID)
	if len(pcs) == 0 {
		pcs = p.GetCachedPoolControllers(ctx, xid)
	}

	jobs := make([]*cmonapi.Job, 0)
	if len(pcs) > 0 && data.Client != nil {
		fetchJobHours := p.Router(ctx).Config.FetchJobsHours
		if fetchJobHours < 1 {
			fetchJobHours = 12
		}
		seenJobID := make(map[uint64]bool)
		for _, pc := range pcs {
			if pc == nil || len(pc.Hostname) == 0 || pc.Port == 0 {
				continue
			}
			if len(pc.Status) > 0 && !strings.EqualFold(pc.Status, "active") {
				continue
			}
			inst := data.Client.Instance.Copy()
			inst.Url = fmt.Sprintf("%s:%d", pc.Hostname, pc.Port+1)
			pcClient := cmon.NewClient(inst, p.Router(ctx).Config.Timeout)
			if sess := data.Client.GetSessionCookie(); sess != nil {
				pcClient.SetSessionCookie(sess)
			}
			if list, _ := pcClient.GetLastJobs(nil, fetchJobHours); list != nil {
				for _, j := range list {
					if j == nil || seenJobID[j.JobID] {
						continue
					}
					seenJobID[j.JobID] = true
					jobs = append(jobs, j)
				}
			}
		}
	}
	if len(jobs) == 0 {
		return data.Jobs, controllerID, xid
	}
	return jobs, controllerID, xid
}

// resolveAlarmsSource returns alarms gathered from pool controllers when available
// (querying hostname:(port+1)), otherwise falls back to the main controller cached alarms.
func (p *Proxy) resolveAlarmsSource(ctx *gin.Context, data *router.Cmon) (map[uint64]*cmonapi.GetAlarmsReply, string, string) {
	if data == nil {
		return nil, "", ""
	}
	controllerID := data.PoolID()
	xid := data.Xid()

	pcs := p.GetCachedPoolControllers(ctx, controllerID)
	if len(pcs) == 0 {
		pcs = p.GetCachedPoolControllers(ctx, xid)
	}

	alarmsMap := make(map[uint64]*cmonapi.GetAlarmsReply)
	if len(pcs) > 0 && data.Client != nil {
		// Build cluster IDs by querying clusters from each pool controller
		for _, pc := range pcs {
			if pc == nil || len(pc.Hostname) == 0 || pc.Port == 0 {
				continue
			}
			if len(pc.Status) > 0 && !strings.EqualFold(pc.Status, "active") {
				continue
			}
			inst := data.Client.Instance.Copy()
			inst.Url = fmt.Sprintf("%s:%d", pc.Hostname, pc.Port+1)
			pcClient := cmon.NewClient(inst, p.Router(ctx).Config.Timeout)
			if sess := data.Client.GetSessionCookie(); sess != nil {
				pcClient.SetSessionCookie(sess)
			}
			clustersResp, err := pcClient.GetAllClusterInfo(&cmonapi.GetAllClusterInfoRequest{WithOperation: &cmonapi.WithOperation{Operation: "getAllClusterInfo"}, WithHosts: false, WithTags: true})
			if err != nil || clustersResp == nil || clustersResp.Clusters == nil {
				continue
			}
			for _, cl := range clustersResp.Clusters {
				if cl == nil {
					continue
				}
				// fetch alarms per cluster id
				if areply, _ := pcClient.GetAlarms(cl.ClusterID); areply != nil {
					// merge by cluster id; dedupe alarm ids
					if existing, ok := alarmsMap[cl.ClusterID]; ok && existing != nil {
						seen := make(map[int64]bool)
						for _, a := range existing.Alarms {
							if a != nil {
								seen[a.AlarmId] = true
							}
						}
						for _, a := range areply.Alarms {
							if a == nil || seen[a.AlarmId] {
								continue
							}
							existing.Alarms = append(existing.Alarms, a)
						}
						alarmsMap[cl.ClusterID] = existing
					} else {
						alarmsMap[cl.ClusterID] = areply
					}
				}
			}
		}
	}
	if len(alarmsMap) == 0 {
		return data.Alarms, controllerID, xid
	}
	return alarmsMap, controllerID, xid
}

// resolveAuditEntriesSource returns audit entries gathered from pool controllers when available
// (querying hostname:(port+1)), otherwise falls back to the main controller cached audit entries.
func (p *Proxy) resolveAuditEntriesSource(ctx *gin.Context, data *router.Cmon) (map[uint64]*cmonapi.GetAuditEntriesReply, string, string) {
	if data == nil {
		return nil, "", ""
	}
	controllerID := data.PoolID()
	xid := data.Xid()

	pcs := p.GetCachedPoolControllers(ctx, controllerID)
	if len(pcs) == 0 {
		pcs = p.GetCachedPoolControllers(ctx, xid)
	}

	entriesMap := make(map[uint64]*cmonapi.GetAuditEntriesReply)
	if len(pcs) > 0 && data.Client != nil {
		for _, pc := range pcs {
			if pc == nil || len(pc.Hostname) == 0 || pc.Port == 0 {
				continue
			}
			if len(pc.Status) > 0 && !strings.EqualFold(pc.Status, "active") {
				continue
			}
			inst := data.Client.Instance.Copy()
			inst.Url = fmt.Sprintf("%s:%d", pc.Hostname, pc.Port+1)
			pcClient := cmon.NewClient(inst, p.Router(ctx).Config.Timeout)
			if sess := data.Client.GetSessionCookie(); sess != nil {
				pcClient.SetSessionCookie(sess)
			}
			clustersResp, err := pcClient.GetAllClusterInfo(&cmonapi.GetAllClusterInfoRequest{WithOperation: &cmonapi.WithOperation{Operation: "getAllClusterInfo"}, WithHosts: false, WithTags: false})
			if err != nil || clustersResp == nil || clustersResp.Clusters == nil {
				continue
			}
			for _, cl := range clustersResp.Clusters {
				if cl == nil {
					continue
				}
				if ereply, _ := pcClient.GetAuditEntries(cl.ClusterID); ereply != nil {
					if existing, ok := entriesMap[cl.ClusterID]; ok && existing != nil {
						seen := make(map[string]bool)
						for _, e := range existing.AuditEntries {
							if e != nil {
								k := fmt.Sprintf("%d|%s|%s|%s", e.ClusterID, e.ReportTs.T.UTC().Format(time.RFC3339Nano), e.EntryType, e.Username)
								seen[k] = true
							}
						}
						for _, e := range ereply.AuditEntries {
							if e == nil {
								continue
							}
							k := fmt.Sprintf("%d|%s|%s|%s", e.ClusterID, e.ReportTs.T.UTC().Format(time.RFC3339Nano), e.EntryType, e.Username)
							if seen[k] {
								continue
							}
							existing.AuditEntries = append(existing.AuditEntries, e)
						}
						entriesMap[cl.ClusterID] = existing
					} else {
						entriesMap[cl.ClusterID] = ereply
					}
				}
			}
		}
	}
	if len(entriesMap) == 0 {
		return data.AuditEntries, controllerID, xid
	}
	return entriesMap, controllerID, xid
}