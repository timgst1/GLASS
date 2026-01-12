package app

import (
	"net/http"
	"time"

	"github.com/timgst1/glass/internal/httpapi"
	"github.com/timgst1/glass/internal/service"
)

func BuildHTTPHandler(cfg Config) http.Handler {
	secretSvc := service.NewMemorySecretService(map[string]string{
		"demo": "hello",
	})

	return httpapi.NewRouter(httpapi.Deps{
		SecretService: secretSvc,
	})
}

func BuildServer(cfg Config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:         cfg.HTTP_ADDR,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}
