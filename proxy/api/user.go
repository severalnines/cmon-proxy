package api

import (
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
)

type LoginRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type LoginResponse struct {
	*cmonapi.WithResponseData `json:",inline"`

	User *config.ProxyUser `json:"username,omitempty"`
}
