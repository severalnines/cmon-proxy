package api

import (
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/config"
)

// AddControllerRequest can be used to add or test a cmon instance to the system
type AddControllerRequest struct {
	Controller *config.CmonInstance `json:"controller"`
}

// AddControllerResponse contains the controller status message
type AddControllerResponse struct {
	*cmonapi.Error

	Controller *ControllerStatus `json:"controller"`
}

// RemoveControllerRequest can be sent to remove a controller by URL
type RemoveControllerRequest struct {
	Url string `json:"url"`
}
