package logger
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
	"fmt"
	"log"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	defaultLogger *zap.Logger
	defaultConfig *Config
	fileWriter    *lumberjack.Logger
)

// Config is the logger configuration
type Config struct {
	OutputPaths       []string
	ErrorOutputPaths  []string
	LogFileName       string
	MaxLogSizeMB      int
	Backups           int
	MaxAgeDays        int
	DisableCaller     bool
	DisableStacktrace bool
}

func filewriterZapHook(e zapcore.Entry) error {
	if fileWriter == nil {
		return nil
	}
	fileWriter.Write([]byte(e.Time.Format(time.RFC3339)))
	fileWriter.Write([]byte(fmt.Sprintf(" : (%s) %s\n", e.Level.CapitalString(), e.Message)))
	return nil
}

// New creates a new Production logger and sets as the global logger
func New(cnf *Config) (*zap.Logger, error) {
	logEncoding := os.Getenv("LOG_ENCODING")
	if len(logEncoding) < 3 {
		logEncoding = "console"
	}
	logLevel := os.Getenv("LOG_LEVEL")
	if len(logLevel) < 3 {
		logLevel = "debug"
	}
	level := new(zapcore.Level)
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		log.Fatal(fmt.Errorf("failed to parse LOG_LEVEL %s: %s", logLevel, err.Error()))
	}

	// create file writer if specified
	if len(cnf.LogFileName) > 0 {
		fileWriter = &lumberjack.Logger{
			Filename:   cnf.LogFileName,
			MaxBackups: cnf.Backups,
			MaxAge:     cnf.MaxAgeDays,
			MaxSize:    cnf.MaxLogSizeMB,
			Compress:   true,
		}
	}

	cfg := zap.NewProductionConfig()
	cfg.DisableCaller = cnf.DisableCaller
	cfg.DisableStacktrace = cnf.DisableStacktrace
	cfg.Encoding = logEncoding
	cfg.Level = zap.NewAtomicLevelAt(*level)
	cfg.OutputPaths = cnf.OutputPaths
	cfg.ErrorOutputPaths = cnf.ErrorOutputPaths
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, err := cfg.Build(zap.Hooks(filewriterZapHook))
	if err != nil {
		return nil, fmt.Errorf("failed to build logger config: %+v", err)
	}
	zap.ReplaceGlobals(logger)
	return logger, nil
}

func DefaultConfig() *Config {
	if defaultConfig == nil {
		defaultConfig = &Config{
			OutputPaths:       []string{"stdout"},
			ErrorOutputPaths:  []string{"stderr"},
			DisableStacktrace: true,
			DisableCaller:     true,
			MaxLogSizeMB:      10,
			Backups:           5,
			MaxAgeDays:        14,
		}
	}
	return defaultConfig
}
