package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/timgst1/glass/internal/service"
)

func (h SecretHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	prefix := normalizePrefix(r.URL.Query().Get("prefix"))
	if prefix == "" {
		http.Error(w, "missing query parameter: prefix", http.StatusBadRequest)
		return
	}

	withMeta := r.URL.Query().Get("withMeta") == "true" || r.URL.Query().Get("withMeta") == "1"

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "map"
	}
	if format != "map" && format != "list" {
		http.Error(w, "invalid query parameter: format (use map|list)", http.StatusBadRequest)
		return
	}

	keysMode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("keys")))
	if keysMode == "" {
		keysMode = "relative"
	}
	if keysMode != "relative" && keysMode != "full" {
		http.Error(w, "invalid query parameter: keys (use relative|full)", http.StatusBadRequest)
		return
	}

	// Relative Keys sollen keine "/" enthalten -> flatten=true ist Default
	flatten := true
	flattenParam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("flatten")))
	if flattenParam == "false" || flattenParam == "0" {
		flatten = false
	}

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

	if format == "list" {
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
		return
	}

	// map output (default)
	stripPrefix := prefix
	if stripPrefix != "" && !strings.HasSuffix(stripPrefix, "/") {
		stripPrefix += "/"
	}

	mapKey := func(fullKey string) string {
		if keysMode == "full" {
			return fullKey
		}
		k := strings.TrimPrefix(fullKey, stripPrefix)
		k = strings.TrimPrefix(k, "/")
		if flatten {
			k = strings.ReplaceAll(k, "/", "_")
		}
		return k
	}

	if !withMeta {
		data := make(map[string]string, len(items))
		for _, it := range items {
			k := mapKey(it.Key)
			if k == "" {
				continue
			}
			data[k] = it.Value
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		return
	}

	type metaVal struct {
		Value     string `json:"value"`
		Version   int64  `json:"version"`
		CreatedAt string `json:"created_at"`
		CreatedBy string `json:"created_by"`
	}

	data := make(map[string]metaVal, len(items))
	for _, it := range items {
		k := mapKey(it.Key)
		if k == "" {
			continue
		}
		data[k] = metaVal{
			Value:     it.Value,
			Version:   it.Version,
			CreatedAt: it.CreatedAt,
			CreatedBy: it.CreatedBy,
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}
