package metering

// Copyright 2026 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"github.com/severalnines/cmon-proxy/multi/router"
)

// RouterAdapter wraps a Router to implement ClusterDataProvider.
type RouterAdapter struct {
	router *router.Router
}

// NewRouterAdapter creates a ClusterDataProvider backed by a Router.
func NewRouterAdapter(r *router.Router) *RouterAdapter {
	return &RouterAdapter{router: r}
}

// FetchAllClusters forces a cache refresh and returns per-controller cluster data.
func (a *RouterAdapter) FetchAllClusters() map[string]*ControllerClusters {
	// Force refresh from all backends.
	a.router.GetAllClusterInfo(true)

	result := make(map[string]*ControllerClusters)

	for _, addr := range a.router.Urls() {
		cmon := a.router.Cmon(addr)
		if cmon == nil {
			continue
		}

		cc := &ControllerClusters{
			ControllerID: addr,
		}

		// Use the controller's unique ID (xid or pool ID) if available.
		if xid := cmon.Xid(); xid != "" {
			cc.ControllerID = xid
		}

		if cmon.Clusters != nil {
			cc.Clusters = cmon.Clusters.Clusters
		}

		result[addr] = cc
	}

	return result
}
