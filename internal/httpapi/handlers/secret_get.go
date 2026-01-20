package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/timgst1/glass/internal/service"
)

type SecretHandler struct {
	Secrets service.SecretService
}

func (h SecretHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing query parameter: key", http.StatusBadRequest)
		return
	}

	val, err := h.Secrets.GetSecret(r.Context(), key)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"value": val})
}
