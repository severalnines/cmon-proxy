package proxy

import (
	"fmt"
	"time"

	"github.com/severalnines/cmon-proxy/cmon"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

type Router struct {
	Config      *config.Config
	Clients     map[string]*cmon.Client
	Timestamps  map[string]time.Time
	LastReqs    map[string]interface{}
	LastReplies map[string]interface{}
}

func NewRouter(config *config.Config) (*Router, error) {
	if config == nil {
		return nil, fmt.Errorf("Invalid configuration")
	}

	return &Router{
		Config:      config,
		Clients:     make(map[string]*cmon.Client),
		Timestamps:  make(map[string]time.Time),
		LastReqs:    make(map[string]interface{}),
		LastReplies: make(map[string]interface{}),
	}, nil
}

// Authenticate will does an inital authentication request to the cmon instances
func (router *Router) Authenticate() {
	logger := zap.L().Sugar()
	for _, instance := range router.Config.Instances {
		addr := instance.Url
		router.Timestamps[addr] = time.Now()
		router.Clients[addr] = cmon.NewClient(instance, router.Config.Timeout)

		// howto return how many cmons has failed to authenticated and why?
		if err := router.Clients[addr].Authenticate(); err != nil {
			logger.Warnf("Cmon [%s] auth failure: %s", addr, err.Error())
		} else {
			// if any has passed we are good
			user := router.Clients[addr].User()
			logger.Infof("Cmon [%s] auth succed with user %s", addr, user.UserName)
		}
	}
}
