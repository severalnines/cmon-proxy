package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Config holds the configuration of cmon-proxy, it is pretty minimal now
type Config struct {
	Filename string
	Urls     []string `yaml:"urls,omitempty"`
	Timeout  int      `yaml:"timeout,omitempty"`
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
	return config, nil
}
