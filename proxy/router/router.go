package router

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
	GetClustersErrCounter int
	GetClustersErr        error
	PingError             error
	LastJobsRefresh       time.Time
	Jobs                  []*api.Job
	LastBackupsRefresh    time.Time
	BackupSchedules       []*api.Job
	Backups               []*api.Backup
	mtx                   *sync.Mutex
}

type Router struct {
	Config *config.Config
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
		if c, found := router.cmons[addr]; !found || c == nil {
			if instance := router.Config.ControllerByUrl(addr); instance != nil {
				router.cmons[addr] = &Cmon{
					Client: cmon.NewClient(instance, router.Config.Timeout),
					mtx:    &sync.Mutex{},
					Alarms: make(map[uint64]*api.GetAlarmsReply),
				}
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
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil || time.Since(c.LastPing) < time.Duration(pingInterval)*time.Second {
			continue
		}

		// ping now
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true
			pingResp, err := c.Client.Ping()

			// to protect againts concurrent writes
			c.mtx.Lock()
			c.LastPing = time.Now()
			c.PingResponse = pingResp
			c.PingError = err
			c.mtx.Unlock()
		}()
	}

	wg.Wait()
}

func (router *Router) GetAllClusterInfo(forceUpdate bool) {
	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}
		var lastUpdated time.Time
		if c.Clusters != nil && c.Clusters.WithResponseData != nil {
			lastUpdated = c.Clusters.RequestProcessed
		}
		if !forceUpdate &&
			(time.Since(lastUpdated) < time.Duration(pingInterval)*time.Second) {
			continue
		}

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
				WithLicenseCheck: false,
				WithHosts:        true,
				WithTags:         true,
			})

			// to protect againts concurrent writes
			c.mtx.Lock()
			if listResp != nil && listResp.Clusters != nil {
				c.Clusters = listResp
				c.GetClustersErr = nil
				c.GetClustersErrCounter = 0
			}
			if err != nil {
				fmt.Println("Cmon query error", err.Error())
				// store the error and increase the counter
				c.GetClustersErrCounter++
				c.GetClustersErr = err
			}
			c.mtx.Unlock()
		}()
	}

	wg.Wait()

}

func (router *Router) GetAlarms(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

	wg := &sync.WaitGroup{}
	syncChannel := make(chan bool, parallelLevel)
	mtx := &sync.Mutex{}

	for _, addr := range router.Urls() {
		c := router.Cmon(addr)
		if c == nil {
			continue
		}
		var lastUpdated time.Time
		if len(c.Alarms) > 0 {
			for _, reply := range c.Alarms {
				if reply != nil && reply.WithResponseData != nil {
					lastUpdated = reply.RequestProcessed
					break
				}
			}
		}
		if !forceUpdate &&
			(time.Since(lastUpdated) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		updatedAlarms := make(map[uint64]*api.GetAlarmsReply)

		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			for _, cid := range c.ClusterIDs() {
				if alarms, _ := c.Client.GetAlarms(cid); alarms != nil {
					mtx.Lock()
					updatedAlarms[cid] = alarms
					mtx.Unlock()
				}
			}
		}()

		c.mtx.Lock()
		c.Alarms = updatedAlarms
		c.mtx.Unlock()
	}

	wg.Wait()
}

func (router *Router) GetLastJobs(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

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

		wg.Add(1)
		go func() {
			cids := c.ClusterIDs()
			updatedJobs := make([]*api.Job, 0, len(cids))

			defer func() {
				c.mtx.Lock()
				c.Jobs = updatedJobs
				c.LastJobsRefresh = time.Now()
				c.mtx.Unlock()
				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			// get the jobs from last 12hours
			jobs, err := c.Client.GetLastJobs(cids, fetchJobHours)
			if err != nil {
				fmt.Println("ERROR???", err.Error())
			}
			if err == nil {
				for _, job := range jobs {
					updatedJobs = append(updatedJobs, job)
				}
			}
		}()
	}

	wg.Wait()
}

func (cmon *Cmon) ControllerID() string {
	if cmon == nil {
		return ""
	}
	cmon.mtx.Lock()
	defer cmon.mtx.Unlock()

	if cmon.PingResponse == nil {
		if cmon.Client == nil {
			return ""
		}

		// return the controller ID from the parsed headers
		return cmon.Client.ControllerID()
	}

	// return the controller ID from the last ping reply
	return cmon.PingResponse.ControllerID
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

	if cmon.Clusters == nil || len(cmon.Clusters.Clusters) < 1 {
		return ""
	}

	for _, cluster := range cmon.Clusters.Clusters {
		if cluster.ClusterID == clusterId {
			return cluster.ClusterType
		}
	}

	return ""
}

func (router *Router) GetBackups(forceUpdate bool) {
	// make sure we have clusters data
	router.GetAllClusterInfo(false)

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
		if !forceUpdate &&
			(time.Since(c.LastBackupsRefresh) < time.Duration(pingInterval)*time.Second) {
			continue
		}

		// Fetch the list of backups
		wg.Add(1)
		go func() {
			defer wg.Done()
			cids := c.ClusterIDs()

			backups, err := c.Client.GetLastBackups(cids, fetchBackupDays)
			if err == nil {
				c.mtx.Lock()
				c.Backups = backups
				c.LastBackupsRefresh = time.Now()
				c.mtx.Unlock()
			}
		}()

		// and also pull/refresh the scheduled backup jobs
		wg.Add(1)
		go func() {
			cids := c.ClusterIDs()
			updatedJobs := make([]*api.Job, 0, len(cids))

			defer func() {
				c.mtx.Lock()
				c.BackupSchedules = updatedJobs
				c.LastBackupsRefresh = time.Now()
				c.mtx.Unlock()

				wg.Done()
				<-syncChannel
			}()
			syncChannel <- true

			jobs, err := c.Client.GetBackupJobs(cids)
			if err == nil {
				for _, job := range jobs {
					updatedJobs = append(updatedJobs, job)
				}
			}
		}()
	}

	wg.Wait()
}
