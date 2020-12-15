package rpcserver

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Middleware attaches CORS (access-control-allow-*) headers
// to gin.Context on every request to allow cross-domain
// requests from the frontend.
func Middleware(ctx *gin.Context) {
	origin := ctx.GetHeader("origin")
	if origin == "" {
		origin = "*"
	}
	ctx.Header("access-control-allow-origin", origin)
	ctx.Header("access-control-allow-headers", "content-type, accept")
	ctx.Header("access-control-allow-credentials", "true")
	ctx.Next()
}

// Options handles all options request
func Options(ctx *gin.Context) {
	ctx.Header("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE")
	ctx.Status(http.StatusOK)
}
