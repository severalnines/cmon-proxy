package config

import (
	"fmt"
	"io/ioutil"
	"sync"

	cmonapi "github.com/severalnines/cmon-proxy/cmon/api"
	"github.com/severalnines/cmon-proxy/logger"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type CmonInstance struct {
	Url      string   `yaml:"url" json:"url"`
	Name     string   `yaml:"name,omitempty" json:"name,omitempty"`
	Username string   `yaml:"username,omitempty" json:"username,omitempty`
	Password string   `yaml:"password,omitempty" json:"password,omitempty"`
	Keyfile  string   `yaml:"keyfile,omitempty" json:"keyfile,omitempty"`
	Tags     []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// Config holds the configuration of cmon-proxy, it is pretty minimal now
type Config struct {
	Filename  string
	Instances []*CmonInstance `yaml:"instances,omitempty"`
	Timeout   int             `yaml:"timeout,omitempty"`
	Logfile   string          `yaml:"logfile,omitempty"`

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
func Load(filename string) (*Config, error) {
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
		config.Logfile = "cmon-proxy.log"
	}

	// re-create the logger using the specified file name
	loggerConfig := logger.DefaultConfig()
	loggerConfig.LogFileName = config.Logfile
	logger.New(loggerConfig) // this replaces the global

	zap.L().Info(fmt.Sprintf("Loaded configuration (%d cmon instances)", len(config.Instances)))
	zap.L().Info(fmt.Sprintf("Using logfile %s", config.Logfile))

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
