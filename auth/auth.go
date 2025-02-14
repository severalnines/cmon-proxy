package auth

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/severalnines/clustercontrol-k8s/auth/jwt"
	"github.com/severalnines/cmon-proxy/auth/internal/whoami"
)

// Auth represents the authentication service
type Auth struct {
	jwtSecret []byte
	whoamiURL string
	client    *http.Client
	mu        sync.RWMutex
}

// Options contains configuration options for the Auth service
type Options struct {
	// JWTSecret is optional, if not provided a random secret will be generated
	JWTSecret []byte
	WhoamiURL string
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

	// Create a custom HTTP client that ignores certificate issues
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	return &Auth{
		jwtSecret: secret,
		whoamiURL: opts.WhoamiURL,
		client:    client,
	}, nil
}

// NewAuth creates a new Auth instance with provided JWT secret (legacy constructor)
func NewAuth(jwtSecret []byte, whoamiURL string) *Auth {
	auth, _ := New(Options{
		JWTSecret: jwtSecret,
		WhoamiURL: whoamiURL,
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

// GenerateToken generates a new JWT token for the given cmon-sid
func (a *Auth) GenerateToken(cmonSID string) (string, error) {
	user, err := whoami.GetUserInfo(a.whoamiURL, cmonSID, a.client)
	if err != nil {
		return "", err
	}

	tokenData := map[string]interface{}{
		"username": user.UserName,
		"roles":    user.Groups,
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
	cmonSID, err := r.Cookie("cmon-sid")
	if err != nil {
		http.Error(w, "Missing cmon-sid cookie", http.StatusBadRequest)
		return
	}
	log.Printf("cmon-sid: %s", cmonSID.Value)

	token, err := a.GenerateToken(cmonSID.Value)
	if err != nil {
		log.Printf("Error generating token: %v", err)
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
