package app

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	HTTP_ADDR        string
	HTTP_PORT        string
	LOG_LEVEL        string
	SHUTDOWN_TIMEOUT string
	READINESS_STRICT string
	AUTH_TOKEN_FILE  string
	AUTH_MODE        string
	POLICY_FILE      string
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
		cfg.HTTP_ADDR = "0.0.0.0:" + cfg.HTTP_PORT
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

	//AUTH_TOKEN_FILE
	cfg.AUTH_TOKEN_FILE = os.Getenv("AUTH_TOKEN_FILE")

	//AUTH_MODE
	if cfg.AUTH_MODE == "" {
		cfg.AUTH_MDOE = "bearer"
	}
	switch cfg.AUTH_MODE {
	case "bearer":
		if strings.TrimSpace(cfg.AUTH_TOKEN_FILE) == "" {
			return nil, fmt.Errorf("AUTH_TOKEN_FILE is required when AUTH_MODE=bearer")
		}
	case "noop":
		//lokale entwicklung
	default:
		return nil, fmt.Errorf("invalid AUTH_MODE: %q (allowed: bearer, noop)", cfg.AUTH_MODE)
	}

	//POLICY_FILE
	cfg.POLICY_FILE = os.Getenv("POLICY_FILE")
	if cfg.POLICY_FILE == "" {
		return nil, fmt.Errorf("POLICY_FILE is required")
	}

	return cfg, nil
}
