package service

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/timgst1/glass/internal/authn"
)

type entry struct {
	Value     string
	Version   int64
	CreatedAt string
	CreatedBy string
}

type MemorySecretService struct {
	mu sync.RWMutex
	m  map[string]entry
}

func NewMemorySecretService(seed map[string]string) *MemorySecretService {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m := map[string]entry{}
	for k, v := range seed {
		m[k] = entry{Value: v, Version: 1, CreatedAt: now, CreatedBy: "seed"}
	}
	return &MemorySecretService{m: m}
}

func (s *MemorySecretService) GetSecret(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.m[key]
	if !ok {
		return "", ErrNotFound
	}
	return e.Value, nil
}

func (s *MemorySecretService) GetSecretMeta(ctx context.Context, key string) (SecretMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.m[key]
	if !ok {
		return SecretMeta{}, ErrNotFound
	}
	return SecretMeta{
		Key:       key,
		Version:   e.Version,
		CreatedAt: e.CreatedAt,
		CreatedBy: e.CreatedBy,
	}, nil
}

func (s *MemorySecretService) ListSecrets(ctx context.Context, prefix string) ([]SecretItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	items := make([]SecretItem, 0, len(keys))
	for _, k := range keys {
		e := s.m[k]
		items = append(items, SecretItem{
			Key:       k,
			Value:     e.Value,
			Version:   e.Version,
			CreatedAt: e.CreatedAt,
			CreatedBy: e.CreatedBy,
		})
	}
	return items, nil
}

func (s *MemorySecretService) PutSecret(ctx context.Context, key, value string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, _ := authn.SubjectFromContext(ctx)
	createdBy := sub.Kind + ":" + sub.Name
	if createdBy == ":" {
		createdBy = "unknown"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	e := s.m[key]
	e.Version++
	if e.Version == 1 {
		e.Version = 1
	}
	e.Value = value
	e.CreatedAt = now
	e.CreatedBy = createdBy
	s.m[key] = e
	return e.Version, nil
}
