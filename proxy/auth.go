package proxy

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	"github.com/severalnines/cmon-proxy/cmon/api"
	"go.uber.org/zap"
)

// Authenticate does authenticates to all cmon instances
func (ml *Router) RPCAuthenticate(ctx *gin.Context) {
	logger := zap.L()

	var req api.AuthenticateRequest
	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": "invalid request"})
		return
	}

	var user *api.User
	authOk := false
	for _, instance := range ml.Config.Instances {
		ml.Timestamps[instance.Url] = time.Now()
		ml.Clients[instance.Url] = cmon.NewClient(instance, ml.Config.Timeout)

		// howto return how many cmons has failed to authenticated and why?
		if err := ml.Clients[instance.Url].Authenticate(); err != nil {
			logger.Sugar().Warnf("Cmon [%s] auth failure: %s", instance.Url, err.Error())
		} else {
			// if any has passed we are good
			authOk = true
			user = ml.Clients[instance.Url].User()
		}
	}

	if !authOk {
		ctx.JSON(http.StatusForbidden, gin.H{"err": "all cmons failed to authenticate"})
		return
	}

	logger.Sugar().Infof("[audit]", user.UserName, "logged in from", ctx.ClientIP())

	ctx.JSON(http.StatusOK, &api.AuthenticateResponse{
		User: user,
	})
}
