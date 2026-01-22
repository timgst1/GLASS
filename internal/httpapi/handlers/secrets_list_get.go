package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/timgst1/glass/internal/service"
)

func (h SecretHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		http.Error(w, "missing query parameter: prefix", http.StatusBadRequest)
		return
	}

	withMeta := r.URL.Query().Get("withMeta") == "true" || r.URL.Query().Get("withMeta") == "1"

	items, err := h.Secrets.ListSecrets(r.Context(), prefix)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if !withMeta {
		type outItem struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		out := make([]outItem, 0, len(items))
		for _, it := range items {
			out = append(out, outItem{Key: it.Key, Value: it.Value})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": out})
		return
	}

	type outItemMeta struct {
		Key       string `json:"key"`
		Value     string `json:"value"`
		Version   int64  `json:"version"`
		CreatedAt string `json:"created_at"`
		CreatedBy string `json:"created_by"`
	}
	out := make([]outItemMeta, 0, len(items))
	for _, it := range items {
		out = append(out, outItemMeta{
			Key:       it.Key,
			Value:     it.Value,
			Version:   it.Version,
			CreatedAt: it.CreatedAt,
			CreatedBy: it.CreatedBy,
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"items": out})
}
