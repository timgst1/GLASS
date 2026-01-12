package app

import (
	"os"
)

type Config struct {
	HTTP_ADDR        string
	HTTP_PORT        string
	LOG_LEVEL        string
	SHUTDOWN_TIMEOUT string
	READINESS_STRICT string
}

func LoadConfig() (Config, error) {
	var cfg Config

	//HTTP_PORT Parsing
	cfg.HTTP_PORT = os.Getenv("HTTP_PORT")
	if cfg.HTTP_PORT == "" {
		cfg.HTTP_PORT = "8080"
	}

	//HTTP_ADDR Parsing
	cfg.HTTP_ADDR = os.Getenv("HTTP_ADDR")
	if cfg.HTTP_ADDR == "" {
		cfg.HTTP_ADDR = "0.0.0.0:8080"
	}

	//LOG_LEVEL Parsing
	cfg.LOG_LEVEL = os.Getenv("LOG_LEVEL")
	if cfg.LOG_LEVEL == "" {
		cfg.LOG_LEVEL = "info"
	}

	//SHUTDOWN_TIMEOUT Parsing
	cfg.SHUTDOWN_TIMEOUT = os.Getenv("SHUTDOWN_TIMEOUT")
	if cfg.SHUTDOWN_TIMEOUT == "" {
		cfg.SHUTDOWN_TIMEOUT = "10"
	}

	//READINESS_STRICT
	cfg.READINESS_STRICT = os.Getenv("READINESS_STRICT")
	if cfg.READINESS_STRICT == "" {
		cfg.READINESS_STRICT = "true"
	}

	return cfg, nil
}
