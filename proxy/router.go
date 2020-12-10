package proxy

import (
	"fmt"
	"time"

	"github.com/severalnines/cmon-proxy/cmon"
	"github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

const (
	// do not ping more frequent than every 30 seconds
	pingInterval = 30
	// the max number of cmon requests made in parallel
	parallelLevel = 8
)

type Router struct {
	Config        *config.Config
	Clients       map[string]*cmon.Client
	LastPing      map[string]time.Time
	PingResponses map[string]*api.PingResponse
	PingErrors    map[string]error
}

func NewRouter(config *config.Config) (*Router, error) {
	if config == nil {
		return nil, fmt.Errorf("Invalid configuration")
	}

	return &Router{
		Config:        config,
		Clients:       make(map[string]*cmon.Client),
		LastPing:      make(map[string]time.Time),
		PingResponses: make(map[string]*api.PingResponse),
		PingErrors:    make(map[string]error),
	}, nil
}

// Authenticate will does an inital authentication request to the cmon instances
func (router *Router) Authenticate() {
	logger := zap.L().Sugar()

	syncChannel := make(chan bool, parallelLevel)

	for _, instance := range router.Config.Instances {
		addr := instance.Url

		// create client if needed
		if cli, found := router.Clients[addr]; !found || cli == nil {
			router.Clients[addr] = cmon.NewClient(instance, router.Config.Timeout)
		}

		// paralell authentication to the cmons
		go func() {
			if err := router.Clients[addr].Authenticate(); err != nil {
				logger.Warnf("Cmon [%s] auth failure: %s", addr, err.Error())
			} else {
				// if any has passed we are good
				user := router.Clients[addr].User()
				logger.Infof("Cmon [%s] auth succed with user %s", addr, user.UserName)
			}

			syncChannel <- true
		}()
	}

	// wait till all finishes
	for i := 0; i < len(router.Config.Instances); i++ {
		<-syncChannel
	}
}

func (router *Router) Ping() {
	syncChannel := make(chan bool, parallelLevel)

	for _, instance := range router.Config.Instances {
		addr := instance.Url

		// do not ping if we did recently
		if time.Since(router.LastPing[addr]) < time.Duration(pingInterval)*time.Second {
			syncChannel <- true
			continue
		}

		// ping now
		router.LastPing[addr] = time.Now()
		go func() {
			pingResp, err := router.Clients[addr].Ping()
			router.LastPing[addr] = time.Now()
			router.PingResponses[addr] = pingResp
			router.PingErrors[addr] = err

			syncChannel <- true
		}()
	}

	// wait till all finishes
	for i := 0; i < len(router.Config.Instances); i++ {
		<-syncChannel
	}
}
