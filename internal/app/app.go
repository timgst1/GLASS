package app

import (
	"context"
	"net/http"
	"time"

	"github.com/timgst1/glass/internal/httpapi"
	"github.com/timgst1/glass/internal/policy"
	"github.com/timgst1/glass/internal/service"
)

type Runtime struct {
	Server        *http.Server
	PolicyManager *policy.Manager
}

func Build(ctx context.Context, cfg Config) (*Runtime, error) {
	pm := policy.NewManager(cfg.POLICY_FILE)
	if err := pm.Start(ctx); err != nil {
		return nil, err
	}

	secretSvc := service.NewMemorySecretService(map[string]string{
		"demo": "hello",
	})

	h := httpapi.NewRouter(httpapi.Deps{
		SecretService: secretSvc,
	})

	srv := BuildServer(cfg, h)

	return &Runtime{
		Server:        srv,
		PolicyManager: pm,
	}, nil
}

func BuildServer(cfg Config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:         cfg.HTTP_ADDR,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}
