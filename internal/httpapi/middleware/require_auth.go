package middleware

import (
	"net/http"

	"github.com/timgst1/glass/internal/authn"
)

func RequireAuth(a authn.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a == nil {
				http.Error(w, "authenticator not configured", http.StatusInternalServerError)
				return
			}
			sub, err := a.Authenticate(r)
			if err != nil {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			r = r.WithContext(authn.WithSubject(r.Context(), sub))
			next.ServeHTTP(w, r)
		})
	}
}
