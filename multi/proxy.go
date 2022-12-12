package multi

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

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"github.com/severalnines/cmon-proxy/multi/api"
	"github.com/severalnines/cmon-proxy/multi/router"
	"go.uber.org/zap"
)

var (
	mtx                   *sync.Mutex
	controllerStatusCache map[string]*api.ControllerStatus
)

type Proxy struct {
	cfg *config.Config
	r   map[string]*router.Router
}

func init() {
	mtx = &sync.Mutex{}
	controllerStatusCache = make(map[string]*api.ControllerStatus)
}

func New(cfg *config.Config) (*Proxy, error) {
	// create the default router (for cmons with static/non-LDAP login)
	r, err := router.New(cfg)
	if err != nil {
		return nil, err
	}

	retval := &Proxy{
		cfg: cfg,
		r:   make(map[string]*router.Router)}

	retval.r[router.DefaultRouter] = r

	return retval, nil
}

func (p *Proxy) Authenticate() {
	if p == nil || p.r == nil {
		return
	}
	// authenticate with the cmons with the static/non-LDAP credentials
	if defaultRouter, found := p.r[router.DefaultRouter]; found {
		defaultRouter.Authenticate()
	}
}

// refreshes all controllers (after add/remove)
func (p *Proxy) Refresh() {
	for _, router := range p.r {
		theRouter := router
		go func() {
			// this manages the add/removals as well
			theRouter.Authenticate()
		}()
	}
}

func (p *Proxy) Router(ctx *gin.Context) *router.Router {
	// get logger
	log := zap.L()

	if isLDAP, ldapUsername := isLDAPSession(ctx); isLDAP {
		if router, found := p.r[ldapUsername]; found {
			return router
		}
	}
	if defaultRouter, found := p.r[router.DefaultRouter]; found {
		return defaultRouter
	}

	// this can't really happen.. unless we are shutting down ?
	log.Sugar().Fatalln("No router available to handle RPC sessions")
	return nil
}
