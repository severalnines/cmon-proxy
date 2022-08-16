package session
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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/severalnines/cmon-proxy/config"
	"go.uber.org/zap"
)

const (
	SessionTTL = time.Hour * 12
	cookieName = "sid"
)

var (
	domain        = os.Getenv("SESSION_DOMAIN")
	authKey       = os.Getenv("SESSION_AUTH_KEY")
	encryptionKey = os.Getenv("SESSION_ENCRYPTION_KEY")
)

// Sessions is the sessions middleware
func Sessions(cfg *config.Config) gin.HandlerFunc {
	return sessions.Sessions(cookieName, getStore(cfg))
}

// Destroy is destroying the session
func SessionDestroy(ctx *gin.Context) {
	ctx.SetCookie(
		cookieName,
		"",
		-1,
		"/", domain,
		false,
		true)
}

func getStore(cfg *config.Config) sessions.Store {
	var store sessions.Store
	store = cookie.NewStore(getSessionKeys()...)
	sTTL := time.Duration(cfg.SessionTtl)
	store.Options(sessions.Options{
		Domain:   domain,
		MaxAge:   int(sTTL.Seconds()),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	})
	return store
}

func getSessionKeys() [][]byte {
	// we could have use fixed defaults.. but lets go with safety,
	// so we generate new auth/encryption keys every time we restart
	if authKey == "" {
		keyBytes := make([]byte, 32)
		rand.Read(keyBytes)
		authKey = hex.EncodeToString(keyBytes)
	}
	if encryptionKey == "" {
		keyBytes := make([]byte, 32)
		rand.Read(keyBytes)
		encryptionKey = hex.EncodeToString(keyBytes)
	}
	authKeyBytes, err := hex.DecodeString(authKey)
	if err != nil {
		zap.L().Fatal(fmt.Sprintf("invalid hex auth-key: %s (%s)", authKey, err.Error()))
	}
	encryptionKeyBytes, err := hex.DecodeString(encryptionKey)
	if err != nil {
		zap.L().Fatal(fmt.Sprintf("invalid hex encryption-key: %s (%s)", encryptionKey, err.Error()))
	}
	return append(make([][]byte, 0), authKeyBytes, encryptionKeyBytes)
}
