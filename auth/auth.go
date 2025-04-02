package auth

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/severalnines/cmon-proxy/auth/jwt"
	"github.com/severalnines/cmon-proxy/auth/providers/cmon"
	"github.com/severalnines/cmon-proxy/auth/user"
	"go.uber.org/zap"
)

// Auth represents the authentication service
type Auth struct {
	jwtSecret []byte
	provider  user.Provider
	mu        sync.RWMutex
	logger    *zap.SugaredLogger
}

// Options contains configuration options for the Auth service
type Options struct {
	// JWTSecret is optional, if not provided a random secret will be generated
	JWTSecret []byte
	Provider  user.Provider
}

// New creates a new Auth instance
func New(opts Options) (*Auth, error) {
	secret := opts.JWTSecret
	if len(secret) == 0 {
		// Generate random JWT secret if not provided
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}

	if opts.Provider == nil {
		return nil, fmt.Errorf("user provider is required")
	}

	return &Auth{
		jwtSecret: secret,
		provider:  opts.Provider,
		logger:    zap.L().Sugar(),
	}, nil
}

// NewAuth creates a new Auth instance with provided JWT secret (legacy constructor)
func NewAuth(jwtSecret []byte, whoamiURL string) *Auth {
	// Create a custom HTTP client that ignores certificate issues
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	cmonProvider := cmon.NewProvider(whoamiURL, client)

	auth, _ := New(Options{
		JWTSecret: jwtSecret,
		Provider:  cmonProvider,
	})
	return auth
}

// GetJWTSecret returns the current JWT secret
func (a *Auth) GetJWTSecret() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.jwtSecret
}

// GetJWTSecretBase64 returns the current JWT secret as base64 string
func (a *Auth) GetJWTSecretBase64() string {
	return base64.StdEncoding.EncodeToString(a.GetJWTSecret())
}

// GetProvider returns the current user provider
func (a *Auth) GetProvider() user.Provider {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.provider
}

// GenerateToken generates a new JWT token from an HTTP request
func (a *Auth) GenerateToken(r *http.Request) (string, error) {
	authCtx := &user.AuthContext{
		Request: r,
	}

	user, err := a.provider.GetUserInfo(authCtx)
	if err != nil {
		return "", err
	}

	tokenData := map[string]interface{}{
		"username": user.UserName,
		"roles":    user.Roles,
	}

	return jwt.CreateToken(tokenData, a.GetJWTSecret(), 20*time.Minute)
}

// ValidateToken validates the given JWT token
func (a *Auth) ValidateToken(token string) (map[string]interface{}, error) {
	claims, err := jwt.ValidateToken(token, a.GetJWTSecret())
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// AuthenticateHandler is the HTTP handler for token generation (used in standalone mode)
func (a *Auth) AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	// Log that we're processing an authentication request
	a.logger.Info("Processing authentication request")

	token, err := a.GenerateToken(r)
	if err != nil {
		a.logger.Errorf("Error generating token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// StartServer starts the standalone auth service (used in standalone mode)
func (a *Auth) StartServer(addr string) error {
	http.HandleFunc("/authenticate", a.AuthenticateHandler)
	return http.ListenAndServe(addr, nil)
}
