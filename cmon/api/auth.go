package api

// AuthenticateRequest the one to star authentication (key or password based)
type AuthenticateRequest struct {
	*WithOperation `json:",inline"`

	UserName string `json:"user_name"`
	Password string `json:"password"`
}

// Authenticate2Request is requested for key based authentication
type Authenticate2Request struct {
	*WithOperation `json:",inline"`

	Signature string `json:"signature"`
}

// AuthenticateResponse the data we get from server for auth reqs
type AuthenticateResponse struct {
	*WithControllerID `json:",inline"`
	*WithResponseData `json:",inline"`

	Challenge string `json:"challenge"`
	User      *User  `json:"user"`
}
