package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/timgst1/glass/internal/service"
)

type putReq struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (h SecretHandler) PutSecret(w http.ResponseWriter, r *http.Request) {
	var in putReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	in.Key = normalizeKey(in.Key)
	if in.Key == "" {
		http.Error(w, "missing field: key", http.StatusBadRequest)
		return
	}

	ver, err := h.Secrets.PutSecret(r.Context(), in.Key, in.Value)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"key":     in.Key,
		"version": ver,
	})
}
