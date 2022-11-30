package rpcserver

// Copyright 2022 Severalnines AB
//
// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

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
	ctx.Header("access-control-allow-methods", "GET,POST,PUT,PATCH,DELETE,HEAD")
	ctx.Status(http.StatusOK)
}
