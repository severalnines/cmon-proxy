package user

// User represents authenticated user information
type User struct {
	UserName string   `json:"user_name"`
	Roles    []string `json:"roles"`
}

// Provider defines an interface for user information providers
type Provider interface {
	// GetUserInfo retrieves user information based on authentication context
	GetUserInfo(authCtx *AuthContext) (*User, error)
}
