package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/timgst1/glass/internal/authn"
	"github.com/timgst1/glass/internal/httpapi/handlers"
	"github.com/timgst1/glass/internal/httpapi/middleware"
	"github.com/timgst1/glass/internal/service"
)

type Deps struct {
	SecretService service.SecretService
	Authenticator authn.Authenticator
}

func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("ok")) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("ready")) })

	sh := handlers.SecretHandler{Secrets: deps.SecretService}

	r.Route("/v1", func(r chi.Router) {
		r.Use(middleware.RequireAuth(deps.Authenticator))
		r.Get("/secret", sh.GetSecret)
		r.Put("/secret", sh.PutSecret)
	})

	return r
}
