package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/ccx/go/cmon"
	"github.com/severalnines/ccx/go/log"
)

// AuthenticateRequest the one to star authentication (key or password based)
type AuthenticateRequest struct {
	Operation string `json:"operation"`
	UserName  string `json:"user_name"`
	Password  string `json:"password"`
}

// Authenticate2Request is requested for key based authentication
type Authenticate2Request struct {
	Operation string `json:"operation"`
	Signature string `json:"signature"`
}

// AuthenticateResponse the data we get from server for auth reqs
type AuthenticateResponse struct {
	*cmon.WithResponseData `json:",inline"`

	Challenge string     `json:"challenge"`
	User      *cmon.User `json:"user"`
}

// Authenticate does authenticates to all cmon instances
func (ml *MultiClient) RPCAuthenticate(ctx *gin.Context) {
	logger := log.L()

	var req AuthenticateRequest
	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": "invalid request"})
		return
	}

	var user *cmon.User
	authOk := false
	for _, theUrl := range ml.Config.Urls {
		if !strings.Contains(theUrl, "://") {
			// golang URL parser requires scheme
			theUrl = "https://" + theUrl
		}
		urlArg, err := url.Parse(theUrl)
		if err != nil {
			logger.Sugar().Warnf("URL parse failure (%s): %s", theUrl, err)
		}
		urlArg.User = url.UserPassword(req.UserName, req.Password)

		ml.Timestamps[theUrl] = time.Now()
		ml.Clients[theUrl] = NewClient(urlArg, "", ml.Config.Timeout)

		// howto return how many cmons has failed to authenticated and why?
		if err := ml.Clients[theUrl].Authenticate(); err != nil {
			logger.Sugar().Warnf("Cmon [%s] auth failure: %s", theUrl, err.Error())
		} else {
			authOk = true
			user = ml.Clients[theUrl].User()
		}
	}

	if !authOk {
		ctx.JSON(http.StatusForbidden, gin.H{"err": "all cmons failed to authenticate"})
		return
	}

	ctx.JSON(http.StatusOK, &AuthenticateResponse{
		User: user,
	})
}
