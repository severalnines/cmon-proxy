package api

type CreateAccountRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	Account *Account `json:"account"`
}

type CreateAccountResponse struct {
	*WithResponseData `json:",inline"`

	Account *Account `json:"account"`
}

type Account struct {
	*WithClassName `json:",inline"`

	Grants             string `json:"grants,omitempty"`
	HostAllow          string `json:"host_allow,omitempty"`
	OwnDatabase        string `json:"own_database,omitempty"`
	Password           string `json:"password,omitempty"`
	PasswordExpired    bool   `json:"password_expired,omitempty"`
	UserName           string `json:"user_name,omitempty"`
	SystemUser         bool   `json:"system_user,omitempty"`
	MaxConnections     int64  `json:"max_connections,omitempty"`
	MaxQuestions       int64  `json:"max_questions,omitempty"`
	MaxUpdates         int64  `json:"max_updates,omitempty"`
	MaxUserConnections int64  `json:"max_user_connections,omitempty"`
}

type ListAccountsRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`
	*WithLimit     `json:",inline"`
}

type ListAccountsResponse struct {
	*WithResponseData `json:",inline"`
	*WithTotal        `json:",inline"`

	Accounts []*Account `json:"accounts"`
}

type DeleteAccountRequest struct {
	*WithOperation `json:",inline"`
	*WithClusterID `json:",inline"`

	Account *Account `json:"account"`
}

type DeleteAccountResponse struct {
	*WithResponseData `json:",inline"`
}
