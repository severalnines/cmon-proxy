package router

// Copyright 2022-2023 Severalnines AB
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
	PingInterval = 60
	// the max number of cmon requests made in parallel
	ParallelLevel = 4
)

const (
	Ping = iota
	Jobs
	Logs
	Audit
	Backups
	Alarms
	Clusters
)

type Cmon struct {
	Client                *cmon.Client
	PingResponse          *api.PingResponse
	Clusters              *api.GetAllClusterInfoResponse
	Alarms                map[uint64]*api.GetAlarmsReply
	Logs                  map[uint64]*api.GetLogsReply
	AuditEntries          map[uint64]*api.GetAuditEntriesReply
	GetClustersErrCounter int
	GetClustersErr        error
	PingError             error
	Jobs                  []*api.Job
	BackupSchedules       []*api.Job
	Backups               []*api.Backup
	LastUpdate            map[uint64]time.Time
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

func (c *Cmon) InvalidateCache() {
	c.mtx.Lock()
	c.LastUpdate = make(map[uint64]time.Time)
	c.mtx.Unlock()
}

func (c *Cmon) cacheValid(cacheKey uint64) bool {
	if c == nil || c.LastUpdate == nil {
		// nothing to do, invalid input, no need to update
		return true
	}
	if val, found := c.LastUpdate[cacheKey]; !found || val.IsZero() {
		// no cache key? it was never fetched
		return false
	}
	if time.Since(c.LastUpdate[cacheKey]) > time.Duration(PingInterval)*time.Second {
		// expired data
		return false
	}
	// looks good
	return true
}

func (c *Cmon) cacheUpdated(cacheKey uint64, t time.Time) {
	if c == nil || c.LastUpdate == nil {
		return
	}
	if t.IsZero() {
		t = time.Now()
	}
	c.LastUpdate[cacheKey] = t
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
					Client:     cmon.NewClient(actualConfig, router.Config.Timeout),
					mtx:        &sync.Mutex{},
					Alarms:     make(map[uint64]*api.GetAlarmsReply),
					LastUpdate: make(map[uint64]time.Time),
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
	syncChannel := make(chan bool, ParallelLevel)

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
	var mtx sync.Mutex
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, ParallelLevel)
	currentTime := time.Now()

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil || c.cacheValid(Ping) {
			continue
		}

		// ping now
		wg.Add(1)
		address := addr
		go func() {
			syncChannel <- true
			pingResp, err := c.Client.Ping()

			mtx.Lock()
			toCommit[address] = &Cmon{
				PingResponse: pingResp,
				PingError:    err,
			}
			mtx.Unlock()

			wg.Done()
			<-syncChannel
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.PingResponse = updated.PingResponse
			cmon.PingError = updated.PingError
			cmon.cacheUpdated(Ping, currentTime)
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetAllClusterInfo(forceUpdate bool) {
	var mtx sync.Mutex
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, ParallelLevel)
	currentTime := time.Now()

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}

		if !forceUpdate && c.cacheValid(Clusters) {
			continue
		}

		address := addr

		// ping now
		wg.Add(1)
		go func() {
			syncChannel <- true
			listResp, err := c.Client.GetAllClusterInfo(&api.GetAllClusterInfoRequest{
				WithOperation:    &api.WithOperation{Operation: "getAllClusterInfo"},
				WithSheetInfo:    false,
				WithDatabases:    false,
				WithLicenseCheck: true,
				WithHosts:        true,
				WithTags:         true,
			})

			mtx.Lock()
			toCommit[address] = &Cmon{
				Clusters:       listResp,
				GetClustersErr: err,
			}
			mtx.Unlock()

			wg.Done()
			<-syncChannel
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
			cmon.cacheUpdated(Clusters, currentTime)
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetAlarms(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	var mtx sync.Mutex
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, ParallelLevel)
	currentTime := time.Now()

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}

		if !forceUpdate && c.cacheValid(Alarms) {
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

			mtx.Lock()
			toCommit[address] = &Cmon{
				Alarms: make(map[uint64]*api.GetAlarmsReply),
			}
			mtx.Unlock()
			for _, cid := range c.ClusterIDs() {
				if alarms, _ := c.Client.GetAlarms(cid); alarms != nil {
					mtx.Lock()
					toCommit[address].Alarms[cid] = alarms
					mtx.Unlock()
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
			cmon.cacheUpdated(Alarms, currentTime)
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetLogs(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	var mtx sync.Mutex
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, ParallelLevel)
	currentTime := time.Now()

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}

		if !forceUpdate && c.cacheValid(Logs) {
			continue
		}

		address := addr

		wg.Add(1)
		go func() {
			syncChannel <- true

			mtx.Lock()
			toCommit[address] = &Cmon{
				Logs: make(map[uint64]*api.GetLogsReply),
			}
			mtx.Unlock()
			for _, cid := range c.ClusterIDs() {
				if logs, _ := c.Client.GetLogs(cid); logs != nil {
					mtx.Lock()
					toCommit[address].Logs[cid] = logs
					mtx.Unlock()
				}
			}

			wg.Done()
			<-syncChannel
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.Logs = updated.Logs
			cmon.cacheUpdated(Logs, currentTime)
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetAuditEntries(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	var mtx sync.Mutex
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, ParallelLevel)
	currentTime := time.Now()

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}

		if !forceUpdate && c.cacheValid(Audit) {
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

			mtx.Lock()
			toCommit[address] = &Cmon{
				AuditEntries: make(map[uint64]*api.GetAuditEntriesReply),
			}
			mtx.Unlock()
			for _, cid := range c.ClusterIDs() {
				if entries, _ := c.Client.GetAuditEntries(cid); entries != nil {
					mtx.Lock()
					toCommit[address].AuditEntries[cid] = entries
					mtx.Unlock()
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
			cmon.cacheUpdated(Audit, currentTime)
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}

func (router *Router) GetLastJobs(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	var mtx sync.Mutex
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, ParallelLevel)
	currentTime := time.Now()

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
		if !forceUpdate && c.cacheValid(Jobs) {
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

			// get the jobs from last 12hours
			if jobs, _ := c.Client.GetLastJobs(c.ClusterIDs(), fetchJobHours); jobs != nil {
				mtx.Lock()
				toCommit[address] = &Cmon{
					Jobs: jobs,
				}
				mtx.Unlock()
			}
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.Jobs = updated.Jobs
			cmon.cacheUpdated(Jobs, currentTime)
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

	var mtx sync.Mutex
	toCommit := make(map[string]*Cmon)
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, ParallelLevel)
	currentTime := time.Now()

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

		if !forceUpdate && c.cacheValid(Backups) {
			continue
		}

		address := addr

		mtx.Lock()
		toCommit[address] = &Cmon{
			Backups:         make([]*api.Backup, 0),
			BackupSchedules: make([]*api.Job, 0),
		}
		mtx.Unlock()

		// Fetch the list of backups
		wg.Add(1)
		go func() {
			defer wg.Done()
			if backups, _ := c.Client.GetLastBackups(nil, fetchBackupDays); backups != nil {
				mtx.Lock()
				toCommit[address].Backups = backups
				mtx.Unlock()
			}
		}()

		// and also pull/refresh the scheduled backup jobs
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			if schedules, _ := c.Client.GetBackupJobs(nil); schedules != nil {
				mtx.Lock()
				toCommit[address].BackupSchedules = schedules
				mtx.Unlock()
			}
		}()
	}

	wg.Wait()

	router.mtx.Lock()
	for address, updated := range toCommit {
		if cmon, found := router.cmons[address]; found && cmon != nil && updated != nil {
			cmon.mtx.Lock()
			cmon.Backups = updated.Backups
			cmon.BackupSchedules = updated.BackupSchedules
			cmon.cacheUpdated(Backups, currentTime)
			cmon.mtx.Unlock()
		}
	}
	router.mtx.Unlock()
}
