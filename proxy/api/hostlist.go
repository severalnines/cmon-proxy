package api

import (
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
)

// ClusterExt is a cmon cluster extended by controller ID / URL fields
type HostExt struct {
	*WithControllerID
	*cmonapi.Host
}

type HostListRequest struct {
	Filters []*Filter `json:"filters"`
}

type HostListReply struct {
	// the hosts after filtration
	Hosts []*HostExt `json:"hosts"`
	// the last update timestamp of each cmon instance
	LastUpdated map[string]*cmonapi.NullTime `json:"last_updated"`
}
