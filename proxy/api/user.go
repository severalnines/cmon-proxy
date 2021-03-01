package api

type ProxUser struct {
	Username     string `yaml:"username,omitempty" json:"username,omitempty`
	EmailAddress string `yaml:"email,omitempty" json:"email,omitempty`
	PasswordHash string `yaml:"passwordhash,omitempty" json:"passwordhash,omitempty"`
	FirstName    string `yaml:"firstname,omitempty" json:"firstname,omitempty"`
	LastName     string `yaml:"lastname,omitempty" json:"lastname,omitempty"`
}
