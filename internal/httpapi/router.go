package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/timgst1/glass/internal/httpapi/handlers"
	"github.com/timgst1/glass/internal/service"
)

type Deps struct {
	SecretService service.SecretService
}

func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	// TODO: middlewares: request-id, logging, recovery
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("ok")) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("ready")) })

	sh := handlers.SecretHandler{Secrets: deps.SecretService}
	r.Get("/v1/secret", sh.GetSecret)

	return r
}
