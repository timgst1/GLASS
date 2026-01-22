package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/timgst1/glass/internal/service"
)

func (h SecretHandler) GetSecretMeta(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.URL.Query().Get("key"))
	if key == "" {
		http.Error(w, "missing query parameter: key", http.StatusBadRequest)
		return
	}

	meta, err := h.Secrets.GetSecretMeta(r.Context(), key)
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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"key":        meta.Key,
		"version":    meta.Version,
		"created_at": meta.CreatedAt,
		"created_by": meta.CreatedBy,
	})
}
