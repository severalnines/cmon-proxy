package api

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
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
)

// ClusterExt is a cmon cluster extended by controller ID / URL fields
type ClusterExt struct {
	*WithControllerID
	*cmonapi.Cluster
	Key string 
}

type ClustersOverviewRequest struct {
	ForceUpdateRequest    `json:",inline"`
	SimpleFilteredRequest `json:",inline"`
}

type ClusterListRequest struct {
	ListRequest        `json:",inline"`
	WithHosts          bool `json:"with_hosts,omitempty"`
	ForceUpdateRequest `json:",inline"`
}

type ClusterListReply struct {
	ListResponse `json:",inline"`
	Clusters     []*ClusterExt                `json:"clusters"`
	LastUpdated  map[string]*cmonapi.NullTime `json:"last_updated"`
}
