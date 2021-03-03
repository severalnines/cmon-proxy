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

	User *config.ProxyUser `json:"user,omitempty"`
}

type UpdateUserRequest struct {
	User *config.ProxyUser `json:"user,omitempty"`
}

type SetPasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}
