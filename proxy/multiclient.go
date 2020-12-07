package proxy

import (
	"fmt"
	"time"

	"github.com/severalnines/cmon-proxy/config"
)

type MultiClient struct {
	Config      *config.Config
	Clients     map[string]*Client
	Timestamps  map[string]time.Time
	LastReqs    map[string]interface{}
	LastReplies map[string]interface{}
}

func NewMultiClient(config *config.Config) (*MultiClient, error) {
	if config == nil {
		return nil, fmt.Errorf("Invalid configuration")
	}

	return &MultiClient{
		Config:      config,
		Clients:     make(map[string]*Client),
		LastReqs:    make(map[string]interface{}),
		LastReplies: make(map[string]interface{}),
	}, nil
}
