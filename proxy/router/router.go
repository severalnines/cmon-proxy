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
	GetClustersErrCounter int
	GetClustersErr        error
	PingError             error
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
		if c == nil || !forceUpdate &&
			(time.Since(c.LastPing) < time.Duration(pingInterval)*time.Second) {
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
