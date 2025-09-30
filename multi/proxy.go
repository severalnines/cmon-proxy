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
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
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
		r:   make(map[string]*router.Router),
	}

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
	for _, r := range p.r {
		theRouter := r
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
		if r, found := p.r[ldapUsername]; found {
			return r
		}
	}
	if isCMON, cmonUsername := isCMONSession(ctx); isCMON {
		if r, found := p.r[cmonUsername]; found {
			return r
		}
	}
	if defaultRouter, found := p.r[router.DefaultRouter]; found {
		return defaultRouter
	}

	// this can't really happen.. unless we are shutting down ?
	log.Sugar().Fatalln("No router available to handle RPC sessions")
	return nil
}

// In case of configuration re-load, lets apply it to all of the routers
func (p *Proxy) UpdateConfig(cfg *config.Config) {
	mtx.Lock()
	p.cfg = cfg
	for _, r := range p.r {
		if r != nil {
			r.Config = cfg
		}
	}
	mtx.Unlock()

	// then refresh all
	p.Refresh()
}

// GetCachedPoolControllers returns any cached pool-controller list associated with
// the controller identified by matchId (xid or controller_id). Falls back to
// instance-level configured controllers if available.
func (p *Proxy) GetCachedPoolControllers(ctx *gin.Context, matchId string) []*cmonapi.PoolController {
    if p == nil {
        return nil
    }
    r := p.Router(ctx)
    if r == nil {
        return nil
    }
    for _, addr := range r.Urls() {
        c := r.Cmon(addr)
        if c == nil {
            continue
        }
        if !c.MatchesID(matchId) {
            continue
        }
        mtx.Lock()
        status := controllerStatusCache[addr]
        mtx.Unlock()
        if status != nil && len(status.Controllers) > 0 {
            return status.Controllers
        }
        if c.Client != nil && c.Client.Instance != nil && len(c.Client.Instance.Controllers) > 0 {
            return c.Client.Instance.Controllers
        }
        break
    }
    return nil
}
