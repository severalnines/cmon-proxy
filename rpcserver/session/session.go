package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
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
func Sessions() gin.HandlerFunc {
	return sessions.Sessions(cookieName, getStore())
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

func getStore() sessions.Store {
	var store sessions.Store
	store = cookie.NewStore(getSessionKeys()...)
	ttl := os.Getenv("SESSION_TTL")
	sTTL := SessionTTL
	if ttl != "" {
		s, err := strconv.ParseInt(ttl, 10, 0)
		if err != nil {
			zap.L().Fatal(fmt.Sprintf("invalid value for SESSION_TTL env variable \"%s\": %v\n", ttl, err))
		}
		sTTL = time.Second * time.Duration(s)
	}
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
