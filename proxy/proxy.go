package proxy

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
