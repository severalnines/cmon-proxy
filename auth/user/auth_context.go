package user

import (
	"net/http"
)

type AuthContext struct {
	Request *http.Request
}
