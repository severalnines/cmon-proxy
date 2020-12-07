package config

import (
	"fmt"
	"io/ioutil"

	"github.com/severalnines/cmon-proxy/logger"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type CmonInstance struct {
	Url      string `yaml:"url,omitempty"`
	Name     string `yaml:"name,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Keyfile  string `yaml:"keyfile,omitempty"`
}

// Config holds the configuration of cmon-proxy, it is pretty minimal now
type Config struct {
	Filename  string
	Instances []*CmonInstance `yaml:"instances,omitempty"`
	Timeout   int             `yaml:"timeout,omitempty"`
	Logfile   string          `yaml:"logfile,omitempty"`
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
	if config.Timeout <= 30 {
		config.Timeout = 30
	}
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
