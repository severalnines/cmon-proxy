package config

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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	"github.com/severalnines/cmon-proxy/auth/secret"
	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/env"
	"github.com/severalnines/cmon-proxy/logger"
	"github.com/severalnines/cmon-proxy/opts"
	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"
)

type ProxyUser struct {
	Username     string   `yaml:"username,omitempty" json:"username,omitempty"`
	EmailAddress string   `yaml:"email,omitempty" json:"email,omitempty"`
	PasswordHash string   `yaml:"passwordhash,omitempty" json:"passwordhash,omitempty"`
	FirstName    string   `yaml:"firstname,omitempty" json:"firstname,omitempty"`
	LastName     string   `yaml:"lastname,omitempty" json:"lastname,omitempty"`
	LdapUser     bool     `yaml:"ldap,omitempty" json:"ldap,omitempty"`
	CMONUser     bool     `yaml:"cmon,omitempty" json:"cmon,omitempty"`
	Admin        bool     `yaml:"admin,omitempty" json:"admin,omitempty"`
	Groups       []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	ControllerId string   `yaml:"xid,omitempty" json:"xid,omitempty"`
}

type CmonInstance struct {
	Xid           string `yaml:"xid" json:"xid"`
	Url           string `yaml:"url" json:"url"`
	Name          string `yaml:"name,omitempty" json:"name,omitempty"`
	Username      string `yaml:"username,omitempty" json:"username,omitempty"`
	Password      string `yaml:"password,omitempty" json:"password,omitempty"`
	Keyfile       string `yaml:"keyfile,omitempty" json:"keyfile,omitempty"`
	FrontendUrl   string `yaml:"frontend_url,omitempty" json:"frontend_url,omitempty"`
	CMONSshHost   string `yaml:"cmon_ssh_host,omitempty" json:"cmon_ssh_host,omitempty"`
	CMONSshSecure bool   `yaml:"cmon_ssh_secure,omitempty" json:"cmon_ssh_secure,omitempty"`
}

// Config holds the configuration of cmon-proxy, it is pretty minimal now
type Config struct {
	Filename          string
	WebAppRoot        string
	FetchJobsHours    int             `yaml:"fetch_jobs_hours,omitempty" json:"fetch_jobs_hours,omitempty"`
	FetchBackupDays   int             `yaml:"fetch_backups_days,omitempty" json:"fetch_backups_days,omitempty"`
	Instances         []*CmonInstance `yaml:"instances,omitempty"`
	Timeout           int             `yaml:"timeout,omitempty"`
	Logfile           string          `yaml:"logfile,omitempty"`
	Users             []*ProxyUser    `yaml:"users,omitempty"`
	FrontendPath      string          `yaml:"frontend_path,omitempty" json:"frontend_path,omitempty"`
	Port              int             `yaml:"port" json:"port"`
	TlsCert           string          `yaml:"tls_cert,omitempty" json:"tls_cert,omitempty"`
	TlsKey            string          `yaml:"tls_key,omitempty" json:"tls_key,omitempty"`
	SessionTtl        int64           `yaml:"session_ttl" json:"session_ttl"` // in nanoseconds, min 30 minutes
	SingleController  string          `yaml:"single_controller" json:"single_controller"`
	K8sProxyURL       string          `yaml:"k8s_proxy_url" json:"k8s_proxy_url"`
	KubernetesEnabled bool            `yaml:"kubernetes_enabled" json:"kubernetes_enabled"`
	LicenseProxyURL   string          `yaml:"license_proxy_url" json:"license_proxy_url"`

	// Let's Encrypt settings
	AcmeEnabled  bool     `yaml:"acme_enabled,omitempty" json:"acme_enabled,omitempty"`
	AcmeStaging  bool     `yaml:"acme_staging,omitempty" json:"acme_staging,omitempty"`
	AcmeDomains  []string `yaml:"acme_domains,omitempty" json:"acme_domains,omitempty"`
	AcmeEmail    string   `yaml:"acme_email,omitempty" json:"acme_email,omitempty"`
	AcmeCacheDir string   `yaml:"acme_cache_dir,omitempty" json:"acme_cache_dir,omitempty"`
	HTTPPort     int      `yaml:"http_port,omitempty" json:"http_port,omitempty"`

	AcmeDirectoryURL     string `yaml:"acme_directory_url,omitempty" json:"acme_directory_url,omitempty"`
	AcmeAcceptTOS        bool   `yaml:"acme_accept_tos,omitempty" json:"acme_accept_tos,omitempty"`
	AcmeRenewBefore      string `yaml:"acme_renew_before,omitempty" json:"acme_renew_before,omitempty"`
	AcmeHostPolicyStrict bool   `yaml:"acme_host_policy_strict,omitempty" json:"acme_host_policy_strict,omitempty"`

	mtx sync.RWMutex
}

var (
	defaults = &Config{
		FrontendPath:      "/app",
		Logfile:           env.DefaultLogfilePath,
		Port:              19051,
		HTTPPort:          80,
		SessionTtl:        int64(30 * time.Minute),
		Instances:         make([]*CmonInstance, 0),
		FetchBackupDays:   7,
		FetchJobsHours:    12,
		Timeout:           30,
		SingleController:  "",
		KubernetesEnabled: true,
		K8sProxyURL:       "http://127.0.0.1:8080",
		LicenseProxyURL:   "https://severalnines.com/service/lic.php",
		AcmeAcceptTOS:     true,
		AcmeRenewBefore:   "720h",
	}
)

func (cmon *CmonInstance) Verify() error {
	if cmon == nil || len(cmon.Url) < 3 {
		return cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "invalid controller, missing URL")
	}

	return nil
}

func (cmon *CmonInstance) Copy() *CmonInstance {
	instance := &CmonInstance{
		Xid:           cmon.Xid,
		Url:           cmon.Url,
		Name:          cmon.Name,
		Username:      cmon.Username,
		Keyfile:       cmon.Keyfile,
		Password:      cmon.Password,
		FrontendUrl:   cmon.FrontendUrl,
		CMONSshHost:   cmon.CMONSshHost,
		CMONSshSecure: cmon.CMONSshSecure,
	}
	return instance
}

// Save persist the configuration to the file it was loaded from
func (cfg *Config) Save() error {
	cfg.mtx.RLock()
	defer cfg.mtx.RUnlock()

	if cfg == nil || len(cfg.Filename) < 1 {
		return fmt.Errorf("can't save configuration, no file name")
	}

	contents, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(cfg.Filename, contents, 0644)
}

// Makes some upgrades between versions
func (cfg *Config) Upgrade() {
	if cfg == nil || len(cfg.Instances) < 1 {
		return
	}
	changed := false
	// make sure all instances have a local ID
	for _, cmon := range cfg.Instances {
		if len(cmon.Xid) < 4 {
			cmon.Xid = xid.New().String()
			changed = true
		}
	}
	if changed && len(cfg.Filename) > 0 {
		if err := cfg.Save(); err != nil {
			zap.L().Warn("Couldn't save upgraded configuration file", zap.Error(err))
		}
	}
}

// Load loads the configuration from the specified file name
func Load(filename string, loadFromCli ...bool) (*Config, error) {
	config := new(Config)

	// Set default values before unmarshaling
	config.KubernetesEnabled = defaults.KubernetesEnabled
	config.AcmeAcceptTOS = defaults.AcmeAcceptTOS

	defer func() {
		if err := config.Save(); err != nil {
			zap.L().Error("Failed to save config file",
				zap.Error(err))
		}
	}()

	contents, err := ioutil.ReadFile(filename)
	if err == nil && len(contents) > 0 {
		// unmarshal the contents if we could read anything
		err = yaml.Unmarshal(contents, config)
	}
	// for safety reasons
	if _, statErr := os.Stat(filename); statErr == nil && err != nil {
		// file exists but we failed to load, lets back it up
		fileback := filename + ".bak" + time.Now().Format(time.RFC3339)
		if err2 := os.Rename(filename, fileback); err2 != nil {
			zap.L().Error("Failed to rename config file",
				zap.Error(err),
				zap.String("filename", filename),
				zap.String("fileback", fileback))
		}
	}

	config.Filename = filename
	config.WebAppRoot = env.WebAppRoot

	// a default value for docker...
	if len(config.FrontendPath) < 1 {
		config.FrontendPath = defaults.FrontendPath
	}
	if len(config.TlsCert) < 1 {
		config.TlsCert = path.Join(opts.Opts.BaseDir, "server.crt")
	}
	if v := os.Getenv("TLS_CERTIFICATE_FILE"); v != "" {
		config.TlsCert = v
	}
	if len(config.TlsKey) < 1 {
		config.TlsKey = path.Join(opts.Opts.BaseDir, "server.key")
	}
	if v := os.Getenv("TLS_KEY_FILE"); v != "" {
		config.TlsKey = v
	}
	if config.Port <= 0 {
		config.Port = defaults.Port
	}

	if config.HTTPPort <= 0 {
		config.HTTPPort = defaults.HTTPPort
	}
	if v, _ := strconv.Atoi(os.Getenv("HTTP_PORT")); v > 0 {
		config.HTTPPort = v
	}
	if config.AcmeCacheDir == "" {
		config.AcmeCacheDir = path.Join(opts.Opts.BaseDir, "autocert-cache")
	}

	if config.AcmeDirectoryURL == "" {
		if config.AcmeStaging {
			config.AcmeDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		}
	}

	if config.AcmeRenewBefore == "" {
		config.AcmeRenewBefore = defaults.AcmeRenewBefore
	}

	if config.SessionTtl <= defaults.SessionTtl {
		config.SessionTtl = defaults.SessionTtl
	}

	// some env vars are overriding main options
	if port, _ := strconv.Atoi(os.Getenv("PORT")); port > 0 {
		config.Port = port
	}

	if url := os.Getenv("K8S_PROXY_URL"); url != "" {
		config.K8sProxyURL = url
	}
	if config.K8sProxyURL == "" {
		config.K8sProxyURL = defaults.K8sProxyURL
	}

	if config.LicenseProxyURL == "" {
		config.LicenseProxyURL = defaults.LicenseProxyURL
	}

	// we don't want nulls
	if config.Instances == nil {
		config.Instances = defaults.Instances
	}
	// default minimum timeout value
	if config.Timeout <= defaults.Timeout {
		config.Timeout = defaults.Timeout
	}
	// default configuration file name
	if len(config.Logfile) < 1 {
		if len(defaults.Logfile) > 0 {
			config.Logfile = defaults.Logfile
		} else {
			config.Logfile = path.Join(opts.Opts.BaseDir, "ccmgr.log")
		}
	}

	// default values for fetching backups
	if config.FetchBackupDays < 1 {
		config.FetchBackupDays = defaults.FetchBackupDays
	}

	// default values for fetching jobs
	if config.FetchJobsHours < 1 {
		config.FetchJobsHours = defaults.FetchJobsHours
	}

	// re-create the logger using the specified file name
	loggerConfig := logger.DefaultConfig()
	loggerConfig.LogFileName = config.Logfile
	logger.New(loggerConfig) // this replaces the global

	// do not log, and do not create default user when invoked from CLI
	if len(loadFromCli) < 1 || !loadFromCli[0] {
		zap.L().Info(fmt.Sprintf("Loaded configuration (%d cmon instances)", len(config.Instances)))
		zap.L().Info(fmt.Sprintf("Using logfile %s", config.Logfile))
	}

	return config, err
}

// ControllerUrls returns the URLs of the configured controllers
func (cfg *Config) ControllerUrls() []string {
	cfg.mtx.RLock()
	defer cfg.mtx.RUnlock()

	retval := make([]string, len(cfg.Instances))
	for idx, cmon := range cfg.Instances {
		retval[idx] = cmon.Url
	}
	return retval
}

// ControllerByUrl returns a CmonInstance having the specified url
func (cfg *Config) ControllerByUrl(url string) *CmonInstance {
	cfg.mtx.RLock()
	defer cfg.mtx.RUnlock()

	for _, cmon := range cfg.Instances {
		if cmon.Url == url {
			return cmon
		}
	}
	return nil
}

// ControllerById returns a CmonInstance having the specified url or name
func (cfg *Config) ControllerById(idString string) *CmonInstance {
	cfg.mtx.RLock()
	defer cfg.mtx.RUnlock()

	for _, cmon := range cfg.Instances {
		if cmon.Xid == idString || cmon.Url == idString || cmon.Name == idString {
			return cmon
		}
	}
	return nil
}

// AddController adds a controller to the configuration and perists the config
func (cfg *Config) AddController(cmon *CmonInstance, persist bool) error {
	if err := cmon.Verify(); err != nil {
		return err
	}
	if cfg.ControllerByUrl(cmon.Url) != nil {
		return cmonapi.NewError(cmonapi.RequestStatusTryAgain, "duplicated URL")
	}

	// generate our internal IDs
	if len(cmon.Xid) < 4 {
		cmon.Xid = xid.New().String()
	}

	cfg.mtx.Lock()
	cfg.Instances = append(cfg.Instances, cmon)
	cfg.mtx.Unlock()

	if persist {
		return cfg.Save()
	}
	return nil
}

// RemoveConroller removes a cmon instance from config file and persists the configuration
func (cfg *Config) RemoveController(xid string, persist bool) error {
	if cfg.ControllerById(xid) == nil {
		return cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "controller not found")
	}

	cfg.mtx.Lock()
	removeAt := -1
	for idx, cmon := range cfg.Instances {
		if cmon.Xid == xid {
			removeAt = idx
			break
		}
	}
	if removeAt > -1 {
		cfg.Instances[removeAt] = cfg.Instances[len(cfg.Instances)-1]
		cfg.Instances = cfg.Instances[:len(cfg.Instances)-1]
	} else {
		return cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "controller not found")
	}
	cfg.mtx.Unlock()

	if persist {
		return cfg.Save()
	}

	return nil
}

func (user *ProxyUser) Validate() error {
	if user == nil || len(user.Username) < 1 {
		return fmt.Errorf("invalid username")
	}
	if !user.LdapUser {
		if len(user.EmailAddress) > 0 && !strings.Contains(user.EmailAddress, "@") {
			return fmt.Errorf("invalid e-mail")
		}
	}
	// maybe add other validators later on... eg passwordhash
	return nil
}

func (user *ProxyUser) SetPassword(password string) error {
	saltBytes := make([]byte, 8)
	rand.Read(saltBytes) // be optimistic here

	steps, _ := rand.Int(rand.Reader, big.NewInt(10240)) // max rounds
	if steps == nil {
		steps = big.NewInt(1024) // fall back in case of error
	}
	steps = steps.Add(steps, big.NewInt(2560)) // min 2.5k rounds
	encrypted := pbkdf2.Key([]byte(password), saltBytes, int(steps.Int64()), 32, sha256.New)

	user.PasswordHash = fmt.Sprintf("%s:%d:%s",
		hex.EncodeToString(saltBytes),
		steps.Int64(),
		hex.EncodeToString(encrypted))
	return nil
}

func (user *ProxyUser) ValidatePassword(password string) error {
	parts := strings.Split(user.PasswordHash, ":")
	if len(parts) != 3 {
		return fmt.Errorf("internal password validation error")
	}
	saltBytes, _ := hex.DecodeString(parts[0])
	steps, _ := strconv.ParseInt(parts[1], 10, 32)
	encrypted, _ := hex.DecodeString(parts[2])

	encrypted2 := pbkdf2.Key([]byte(password), saltBytes, int(steps), 32, sha256.New)
	if bytes.Compare(encrypted, encrypted2) != 0 {
		return fmt.Errorf("password mismatch")
	}

	return nil
}

func (cfg *Config) GetUser(username string) (*ProxyUser, error) {
	if cfg == nil || len(cfg.Users) < 1 {
		return nil, fmt.Errorf("no configured users")
	}

	cfg.mtx.RLock()
	defer cfg.mtx.RUnlock()
	for _, user := range cfg.Users {
		if user != nil && user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (cfg *Config) AddUser(user *ProxyUser) error {
	if err := user.Validate(); err != nil {
		return err
	}
	if user, _ := cfg.GetUser(user.Username); user != nil {
		return fmt.Errorf("user already exists")
	}

	cfg.mtx.Lock()
	defer cfg.mtx.Unlock()
	if len(cfg.Users) < 1 {
		cfg.Users = make([]*ProxyUser, 0, 1)
	}
	cfg.Users = append(cfg.Users, user)
	return nil
}

func (cfg *Config) UpdateUser(user *ProxyUser) error {
	origUser, err := cfg.GetUser(user.Username)
	if err != nil {
		return err
	}
	if len(user.PasswordHash) < 1 {
		// lets preserve the password hash, UI is not going to send this all
		// the time eg while updating the users last name
		user.PasswordHash = origUser.PasswordHash
	}
	if err := user.Validate(); err != nil {
		return err
	}

	cfg.mtx.Lock()
	defer cfg.mtx.Unlock()
	index := -1
	for idx, u := range cfg.Users {
		if u != nil && u.Username == user.Username {
			index = idx
			break
		}
	}
	if index > -1 {
		cfg.Users[index] = user
	} else {
		return fmt.Errorf("user '%s' not found", user.Username)
	}
	return nil
}

func (cfg *Config) RemoveUser(username string) error {
	cfg.mtx.Lock()
	defer cfg.mtx.Unlock()

	index := -1
	for idx, u := range cfg.Users {
		if u != nil && u.Username == username {
			index = idx
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("user not found")
	}
	// just erase it
	copy(cfg.Users[index:], cfg.Users[index+1:])
	cfg.Users = cfg.Users[:len(cfg.Users)-1]
	return nil
}

func (cfg *Config) EnableMcc(enable bool) error {
	cfg.mtx.Lock()
	defer cfg.mtx.Unlock()

	cfg.SingleController = ""
	return nil
}

func (u *ProxyUser) Copy(withCredentials bool) *ProxyUser {
	c := &ProxyUser{
		Username:     u.Username,
		EmailAddress: u.EmailAddress,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
		LdapUser:     u.LdapUser,
		CMONUser:     u.CMONUser,
		Admin:        u.Admin,
		Groups:       u.Groups,
	}
	// by default we don't want to return password hashes to UI
	if withCredentials {
		c.PasswordHash = u.PasswordHash
	}
	return c
}

// GetJWTSecret returns the JWT secret as bytes, generating and storing a new one if it doesn't exist
func (cfg *Config) GetJWTSecret() ([]byte, error) {
	secretFile := path.Join(opts.Opts.BaseDir, "jwt_secret.key")
	return secret.LoadOrGenerateSecret(secretFile)
}

// GetJWTSecretPath returns the path to the JWT secret file
func (cfg *Config) GetJWTSecretPath() string {
	return path.Join(opts.Opts.BaseDir, "jwt_secret.key")
}
