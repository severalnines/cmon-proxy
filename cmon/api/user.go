package api

import (
	"time"
)

type User struct {
	*WithControllerID `json:",inline"`
	*WithClassName    `json:",inline"`

	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	UserName  string    `json:"user_name"`
	UserID    uint64    `json:"user_id"`
	LastLogin time.Time `json:"last_login"`

	Groups []*Group `json:"groups"`
}
