package router

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
	"sync"
	"time"

	"github.com/severalnines/cmon-proxy/cmon"
	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

const (
	// do not ping more frequent than every 30 seconds
	pingInterval = 60
	// the max number of cmon requests made in parallel
	parallelLevel = 4
)

type Cmon struct {
	Client                *cmon.Client
	LastPing              time.Time
	PingResponse          *api.PingResponse
	Clusters              *api.GetAllClusterInfoResponse
	Alarms                map[uint64]*api.GetAlarmsReply
	Logs                  map[uint64]*api.GetLogsReply
	AuditEntries          map[uint64]*api.GetAuditEntriesReply
	GetClustersErrCounter int
	GetClustersErr        error
	PingError             error
	LastJobsRefresh       time.Time
	Jobs                  []*api.Job
	LastBackupsRefresh    time.Time
	BackupSchedules       []*api.Job
	Backups               []*api.Backup
	mtx                   *sync.Mutex
	// cache members
	controllerID string
}

const (
	DefaultRouter = ":cmon-proxy-default:"
)

type Ldap struct {
	Use      bool
	Username string
	Password string
}

type Router struct {
	Config *config.Config
	Ldap   Ldap
	cmons  map[string]*Cmon
	mtx    *sync.RWMutex
}

// New creates a new cmon router
func New(config *config.Config) (*Router, error) {
	if config == nil {
		return nil, fmt.Errorf("Invalid configuration")
	}

	return &Router{
		Config: config,
		cmons:  make(map[string]*Cmon),
		mtx:    &sync.RWMutex{},
	}, nil
}

// Sync will synchronize the clients with the configuration
func (router *Router) Sync() {
	router.mtx.Lock()
	defer router.mtx.Unlock()

	// first lets remove all the removed instances (for remove API)
	currentClients := make([]string, len(router.cmons))
	for addr := range router.cmons {
		currentClients = append(currentClients, addr)
	}

	for _, addr := range currentClients {
		if router.Config.ControllerByUrl(addr) != nil {
			continue
		}

		delete(router.cmons, addr)
	}

	// and create the new ones
	for _, addr := range router.Config.ControllerUrls() {
		if instance := router.Config.ControllerByUrl(addr); instance != nil {
			actualConfig := &config.CmonInstance{
				Xid:         instance.Xid,
				Url:         instance.Url,
				Name:        instance.Name,
				Username:    instance.Username,
				UseLdap:     instance.UseLdap,
				Keyfile:     instance.Keyfile,
				Password:    instance.Password,
				FrontendUrl: instance.FrontendUrl,
			}
			// in case of LDAP the credentials aren't stored in config, but in runtime only
			if router.Ldap.Use && actualConfig.UseLdap {
				actualConfig.Username = router.Ldap.Username
				actualConfig.Password = router.Ldap.Password
			}
			if c, found := router.cmons[addr]; !found || c == nil {
				router.cmons[addr] = &Cmon{
					Client: cmon.NewClient(actualConfig, router.Config.Timeout),
					mtx:    &sync.Mutex{},
					Alarms: make(map[uint64]*api.GetAlarmsReply),
				}
			} else if c != nil && c.Client != nil {
				// make sure clients always have the latest configuration
				c.Client.Instance = actualConfig
			}
		}
	}
}

func (router *Router) Cmon(addr string) *Cmon {
	router.mtx.RLock()
	defer router.mtx.RUnlock()

	if cmon, found := router.cmons[addr]; found && cmon != nil {
		return cmon
	}
	return nil
}

func (router *Router) Client(addr string) *cmon.Client {
	if c := router.Cmon(addr); c != nil {
		return c.Client
	}
	return nil
}

func (router *Router) Urls() []string {
	router.mtx.RLock()
	defer router.mtx.RUnlock()

	addrs := make([]string, len(router.cmons))
	for addr := range router.cmons {
		addrs = append(addrs, addr)
	}
	return addrs
}

// Authenticate will does an inital authentication request to the cmon instances
func (router *Router) Authenticate() {
	logger := zap.L().Sugar()

	// we must be in sync with the configuration
	router.Sync()

	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		cli := router.Client(addr)
		if cli == nil {
			continue // removed in the mean time
		}

		// paralell authentication to the cmons
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true
			if cli != nil {
				if err := cli.Authenticate(); err != nil {
					logger.Warnf("Cmon [%s] auth failure: %s", cli.Instance.Url, err.Error())
				} else {
					// if any has passed we are good
					user := cli.User()
					logger.Infof("Cmon [%s] auth succed with user %s", cli.Instance.Url, user.UserName)
				}
			}
		}()
	}

	wg.Wait()
}

// Ping pings the controllers to see their statuses
func (router *Router) Ping() {
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil || time.Since(c.LastPing) < time.Duration(pingInterval)*time.Second {
			continue
		}

		// ping now
		wg.Add(1)
		address := addr
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true
			pingResp, err := c.Client.Ping()

			toCommit[address] = &Cmon{
				LastPing:     time.Now(),
				PingResponse: pingResp,
				PingError:    err,
			}
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.LastPing = updated.LastPing
			cmon.PingResponse = updated.PingResponse
			cmon.PingError = updated.PingError
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetAllClusterInfo(forceUpdate bool) {
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}
		var lastUpdated time.Time
		if c.Clusters != nil && c.Clusters.WithResponseData != nil {
			lastUpdated = c.Clusters.RequestProcessed.T
		}
		if !forceUpdate &&
			(time.Since(lastUpdated) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		address := addr

		// ping now
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true
			listResp, err := c.Client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
				WithOperation:    &api.WithOperation{Operation: "getAllClusterInfo"},
				WithSheetInfo:    false,
				WithDatabases:    false,
				WithLicenseCheck: true,
				WithHosts:        true,
				WithTags:         true,
			})

			toCommit[address] = &Cmon{
				Clusters:       listResp,
				GetClustersErr: err,
			}
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			if updated.Clusters != nil && updated.Clusters.Clusters != nil {
				cmon.Clusters = updated.Clusters
			}
			cmon.GetClustersErr = updated.GetClustersErr
			if cmon.GetClustersErr == nil {
				cmon.GetClustersErrCounter = 0
			} else {
				cmon.GetClustersErrCounter++
			}
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetAlarms(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}
		var lastUpdated time.Time
		if len(c.Alarms) > 0 {
			for _, reply := range c.Alarms {
				if reply != nil && reply.WithResponseData != nil {
					lastUpdated = reply.RequestProcessed.T
					break
				}
			}
		}

		zap.L().Sugar().Info(
			"ALARMS",
			"forceUpdate", forceUpdate,
			"lastUpdated", lastUpdated.String(),
			"since", time.Since(lastUpdated).String(),
			"cache valid", pingInterval, "s")

		if !forceUpdate &&
			(time.Since(lastUpdated) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		address := addr

		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			toCommit[address] = &Cmon{
				Alarms: make(map[uint64]*api.GetAlarmsReply),
			}
			for _, cid := range c.ClusterIDs() {
				if alarms, _ := c.Client.GetAlarms(cid); alarms != nil {
					toCommit[address].Alarms[cid] = alarms
				}
			}
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.Alarms = updated.Alarms
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetLogs(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}
		var lastUpdated time.Time
		if len(c.Logs) > 0 {
			for _, reply := range c.Logs {
				if reply != nil && reply.WithResponseData != nil {
					lastUpdated = reply.RequestProcessed.T
					break
				}
			}
		}
		if !forceUpdate &&
			(time.Since(lastUpdated) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		address := addr

		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			toCommit[address] = &Cmon{
				Logs: make(map[uint64]*api.GetLogsReply),
			}
			for _, cid := range c.ClusterIDs() {
				if logs, _ := c.Client.GetLogs(cid); logs != nil {
					toCommit[address].Logs[cid] = logs
				}
			}
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.Logs = updated.Logs
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetAuditEntries(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	toCommit := make(map[string]*Cmon)

	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}
		var lastUpdated time.Time
		if len(c.AuditEntries) > 0 {
			for _, reply := range c.AuditEntries {
				if reply != nil && reply.WithResponseData != nil {
					lastUpdated = reply.RequestProcessed.T
					break
				}
			}
		}
		if !forceUpdate &&
			(time.Since(lastUpdated) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		address := addr

		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			toCommit[address] = &Cmon{
				AuditEntries: make(map[uint64]*api.GetAuditEntriesReply),
			}
			for _, cid := range c.ClusterIDs() {
				if entries, _ := c.Client.GetAuditEntries(cid); entries != nil {
					toCommit[address].AuditEntries[cid] = entries
				}
			}
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.AuditEntries = updated.AuditEntries
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetLastJobs(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	// fetch jobs only from the last N hours
	fetchJobHours := router.Config.FetchJobsHours
	if fetchJobHours < 1 {
		// lets load the jobs from the last 12 hours by default
		fetchJobHours = 12
	}

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}
		if !forceUpdate &&
			(time.Since(c.LastJobsRefresh) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		address := addr
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			toCommit[address] = &Cmon{
				LastJobsRefresh: time.Now(),
			}

			// get the jobs from last 12hours
			toCommit[address].Jobs, _ = c.Client.GetLastJobs(c.ClusterIDs(), fetchJobHours)
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.Jobs = updated.Jobs
			cmon.LastJobsRefresh = updated.LastBackupsRefresh
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (cmon *Cmon) MatchesID(id string) bool {
	return id == cmon.Xid() || id == cmon.ControllerID()
}

func (cmon *Cmon) Xid() string {
	if cmon == nil || cmon.Client == nil || cmon.Client.Instance == nil {
		return ""
	}

	return cmon.Client.Instance.Xid
}

func (cmon *Cmon) ControllerID() string {
	if cmon == nil {
		return ""
	}

	if len(cmon.controllerID) < 1 {
		// ID is not known yet
		cmon.mtx.Lock()
		defer cmon.mtx.Unlock()

		if cmon.PingResponse == nil {
			if cmon.Client == nil {
				return ""
			}

			// return the controller ID from the parsed headers
			cmon.controllerID = cmon.Client.ControllerID()
		} else {
			// return the controller ID from the last ping reply
			cmon.controllerID = cmon.PingResponse.ControllerID
		}
	}

	return cmon.controllerID
}

func (cmon *Cmon) ClusterIDs() []uint64 {
	if cmon == nil {
		return nil
	}

	cmon.mtx.Lock()
	defer cmon.mtx.Unlock()

	if cmon.Clusters == nil || len(cmon.Clusters.Clusters) < 1 {
		return nil
	}

	retval := make([]uint64, len(cmon.Clusters.Clusters))
	for idx, cluster := range cmon.Clusters.Clusters {
		retval[idx] = cluster.ClusterID
	}
	return retval
}

func (cmon *Cmon) ClusterType(clusterId uint64) string {
	if cmon == nil || clusterId == 0 {
		return ""
	}

	cmon.mtx.Lock()
	defer cmon.mtx.Unlock()

	if cmon.Clusters == nil {
		return ""
	}

	for _, cluster := range cmon.Clusters.Clusters {
		if cluster.ClusterID == clusterId {
			return cluster.ClusterType
		}
	}

	return ""
}

func (cmon *Cmon) ClusterTags(clusterId uint64) []string {
	if cmon == nil || clusterId == 0 {
		return nil
	}

	cmon.mtx.Lock()
	defer cmon.mtx.Unlock()

	if cmon.Clusters == nil {
		return nil
	}

	for _, cluster := range cmon.Clusters.Clusters {
		if cluster.ClusterID == clusterId {
			return cluster.Tags
		}
	}

	return nil
}

func (router *Router) GetBackups(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	fetchBackupDays := router.Config.FetchBackupDays
	if fetchBackupDays < 1 {
		// lets return the backups from the past week
		fetchBackupDays = 7
	}

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}

		zap.L().Sugar().Info(
			"BACKUP",
			"forceUpdate", forceUpdate,
			"lastUpdated", c.LastBackupsRefresh.String(),
			"since", time.Since(c.LastBackupsRefresh).String(),
			"cache valid", pingInterval, "s")

		if !forceUpdate &&
			(time.Since(c.LastBackupsRefresh) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		address := addr
		clusterIDs := c.ClusterIDs()
		toCommit[address] = &Cmon{
			Backups:            make([]*api.Backup, 0),
			BackupSchedules:    make([]*api.Job, 0),
			LastBackupsRefresh: time.Now(),
		}

		// Fetch the list of backups
		wg.Add(1)
		go func() {
			defer wg.Done()
			toCommit[address].Backups, _ = c.Client.GetLastBackups(clusterIDs, fetchBackupDays)
		}()

		// and also pull/refresh the scheduled backup jobs
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			toCommit[address].BackupSchedules, _ = c.Client.GetBackupJobs(clusterIDs)
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.Backups = updated.Backups
			cmon.BackupSchedules = updated.BackupSchedules
			cmon.LastBackupsRefresh = updated.LastBackupsRefresh
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}
