package config

import (
	"fmt"
	"io/ioutil"

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
}

func (cfg *Config) Save() error {
	if cfg == nil || len(cfg.Filename) < 1 {
		return fmt.Errorf("can't save configuration, no file name")
	}

	contents, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(cfg.Filename, contents, 0644)
}

func Load(filename string) (*Config, error) {
	config := new(Config)

	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}

	if err := yaml.Unmarshal(contents, config); err != nil {
		return config, err
	}

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
