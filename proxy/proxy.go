package proxy
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
	"sync"

	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/proxy/api"
	"github.com/severalnines/cmon-proxy/proxy/router"
)

var (
	mtx                   *sync.Mutex
	controllerStatusCache map[string]*api.ControllerStatus
)

type Proxy struct {
	r *router.Router
}

func init() {
	mtx = &sync.Mutex{}
	controllerStatusCache = make(map[string]*api.ControllerStatus)
}

func New(cfg *config.Config) (*Proxy, error) {
	r, err := router.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Proxy{r: r}, nil
}

func (p *Proxy) Authenticate() {
	p.r.Authenticate()
}
