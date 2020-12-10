package proxy

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/cmon"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"go.uber.org/zap"
)

// Authenticate does authenticates to all cmon instances
func (ml *Router) RPCAuthenticate(ctx *gin.Context) {
	logger := zap.L()

	var req cmonapi.AuthenticateRequest
	if err := ctx.BindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"err": "invalid request"})
		return
	}

	var user *cmonapi.User
	authOk := false
	for _, instance := range ml.Config.Instances {
		addr := instance.Url
		// create client if needed
		if cli, found := ml.Clients[addr]; !found || cli == nil {
			ml.Clients[addr] = cmon.NewClient(instance, ml.Config.Timeout)
		}

		// howto return how many cmons has failed to authenticated and why?
		if err := ml.Clients[addr].Authenticate(); err != nil {
			logger.Sugar().Warnf("Cmon [%s] auth failure: %s", instance.Url, err.Error())
		} else {
			// if any has passed we are good
			authOk = true
			user = ml.Clients[addr].User()
		}
	}

	if !authOk {
		ctx.JSON(http.StatusForbidden, gin.H{"err": "all cmons failed to authenticate"})
		return
	}

	logger.Sugar().Infof("[audit]", user.UserName, "logged in from", ctx.ClientIP())

	ctx.JSON(http.StatusOK, &cmonapi.AuthenticateResponse{
		User: user,
	})
}
