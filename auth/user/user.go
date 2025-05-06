package user

type User struct {
	UserName string   `json:"user_name"`
	Roles    []string `json:"roles"`
}

type Provider interface {
	GetUserInfo(authCtx *AuthContext) (*User, error)
}
