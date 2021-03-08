package config

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"
	"sync"

	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/logger"
	"golang.org/x/crypto/pbkdf2"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type ProxyUser struct {
	Username     string `yaml:"username,omitempty" json:"username,omitempty"`
	EmailAddress string `yaml:"email,omitempty" json:"email,omitempty"`
	PasswordHash string `yaml:"passwordhash,omitempty" json:"passwordhash,omitempty"`
	FirstName    string `yaml:"firstname,omitempty" json:"firstname,omitempty"`
	LastName     string `yaml:"lastname,omitempty" json:"lastname,omitempty"`
}

type CmonInstance struct {
	Url         string `yaml:"url" json:"url"`
	Name        string `yaml:"name,omitempty" json:"name,omitempty"`
	Username    string `yaml:"username,omitempty" json:"username,omitempty`
	Password    string `yaml:"password,omitempty" json:"password,omitempty"`
	Keyfile     string `yaml:"keyfile,omitempty" json:"keyfile,omitempty"`
	FrontendUrl string `yaml:"frontend_url,omitempty" json:"frontend_url,omitempty"`
}

// Config holds the configuration of cmon-proxy, it is pretty minimal now
type Config struct {
	Filename        string
	FetchJobsHours  int             `yaml:"fetch_jobs_hours,omitempty" json:"fetch_jobs_hours,omitempty"`
	FetchBackupDays int             `yaml:"fetch_backups_days,omitempty" json:"fetch_backups_days,omitempty"`
	Instances       []*CmonInstance `yaml:"instances,omitempty"`
	Timeout         int             `yaml:"timeout,omitempty"`
	Logfile         string          `yaml:"logfile,omitempty"`
	Users           []*ProxyUser    `yaml:"users,omitempty"`

	mtx *sync.RWMutex
}

func (cmon *CmonInstance) Verify() error {
	if cmon == nil || len(cmon.Url) < 3 {
		return cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "invalid controller, missing URL")
	}
	if len(cmon.Username) < 1 {
		return cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "missing username")
	}
	if len(cmon.Password) < 1 && len(cmon.Keyfile) < 1 {
		return cmonapi.NewError(cmonapi.RequestStatusInvalidRequest, "missing password or keyfile")
	}
	return nil
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

// Load loads the configuration from the specified file name
func Load(filename string, loadFromCli ...bool) (*Config, error) {
	config := new(Config)

	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}

	if err := yaml.Unmarshal(contents, config); err != nil {
		return config, err
	}

	config.mtx = &sync.RWMutex{}
	config.Filename = filename

	// we don't want nulls
	if config.Instances == nil {
		config.Instances = make([]*CmonInstance, 0)
	}
	// default minimum timeout value
	if config.Timeout <= 30 {
		config.Timeout = 30
	}
	// default configuration file name
	if len(config.Logfile) < 1 {
		config.Logfile = "ccmgr.log"
	}

	// re-create the logger using the specified file name
	loggerConfig := logger.DefaultConfig()
	loggerConfig.LogFileName = config.Logfile
	logger.New(loggerConfig) // this replaces the global

	// do not log, and do not create default user when invoked from CLI
	if len(loadFromCli) < 1 || !loadFromCli[0] {
		zap.L().Info(fmt.Sprintf("Loaded configuration (%d cmon instances)", len(config.Instances)))
		zap.L().Info(fmt.Sprintf("Using logfile %s", config.Logfile))

		if len(config.Users) < 1 {
			randBytes := make([]byte, 6)
			rand.Read(randBytes)
			user := &ProxyUser{Username: "admin"}
			user.SetPassword(hex.EncodeToString(randBytes))
			if err := config.AddUser(user); err != nil {
				zap.L().Fatal(fmt.Sprintf("Couldn't create default admin user: %s", err.Error()))
			} else {
				zap.L().Info(fmt.Sprintf("Default 'admin' user has been created with password '%s'", hex.EncodeToString(randBytes)))
			}
			defer config.Save()
		} else {
			zap.L().Info(fmt.Sprintf("Found %d users in configuration", len(config.Users)))
		}
	}

	return config, nil
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

// AddController adds a controller to the configuration and perists the config
func (cfg *Config) AddController(cmon *CmonInstance, persist bool) error {
	if err := cmon.Verify(); err != nil {
		return err
	}
	if cfg.ControllerByUrl(cmon.Url) != nil {
		return cmonapi.NewError(cmonapi.RequestStatusTryAgain, "duplicated URL")
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
func (cfg *Config) RemoveController(url string, persist bool) error {
	if cfg.ControllerByUrl(url) == nil {
		return cmonapi.NewError(cmonapi.RequestStatusObjectNotFound, "controller not found")
	}

	cfg.mtx.Lock()
	removeAt := -1
	for idx, cmon := range cfg.Instances {
		if cmon.Url == url {
			removeAt = idx
			break
		}
	}
	if removeAt > -1 {
		cfg.Instances[removeAt] = cfg.Instances[len(cfg.Instances)-1]
		cfg.Instances = cfg.Instances[:len(cfg.Instances)-1]
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
	if len(user.EmailAddress) > 0 && !strings.Contains(user.EmailAddress, "@") {
		return fmt.Errorf("invalid e-mail")
	}
	// maybe add other validators later on... eg passwordhash
	return nil
}

func (user *ProxyUser) SetPassword(password string) error {
	saltBytes := make([]byte, 8)
	rand.Read(saltBytes) // be optimistic here

	steps, _ := rand.Int(rand.Reader, big.NewInt(4000)) // so max 5k rounds
	if steps == nil {
		steps = big.NewInt(123) // fall back in case of error
	}
	steps = steps.Add(steps, big.NewInt(1000)) // min 1000 rounds
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

func (u *ProxyUser) Copy(withCredentials bool) *ProxyUser {
	c := &ProxyUser{
		Username:     u.Username,
		EmailAddress: u.EmailAddress,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
	}
	// by default we don't want to return password hashes to UI
	if withCredentials {
		c.PasswordHash = u.PasswordHash
	}
	return c
}
