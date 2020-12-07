package logger

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
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

func GinZapFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		// some evil middlewares modify this values
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()

		if len(c.Errors) > 0 {
			// log arr errors
			for _, e := range c.Errors.Errors() {
				defaultLogger.Error(e)
			}
		} else {
			httpStatus := c.Copy().Writer.Status()
			if httpStatus >= 200 && httpStatus < 300 {
				// okay status.. debug log is enough
				zap.L().Sugar().Debugf("RPC [%s] %s %s?%s, status %d",
					c.ClientIP(), c.Request.Method,
					path, query, httpStatus)
			} else {
				// any non 2xx status will go with info level
				zap.L().Sugar().Infof("RPC [%s] %s %s?%s, status %d",
					c.ClientIP(), c.Request.Method,
					path, query, httpStatus)
			}
		}
	}
}

// New creates a new Production logger and sets as the global logger
func New(cnf *Config) (*zap.Logger, error) {
	logEncoding := os.Getenv("LOG_ENCODING")
	if len(logEncoding) < 3 {
		logEncoding = "console"
	}
	logLevel := os.Getenv("LOG_LEVEL")
	if len(logLevel) < 3 {
		logLevel = "info"
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
