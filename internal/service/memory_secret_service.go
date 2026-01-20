package service

import (
	"context"
	"sync"
)

type entry struct {
	Value   string
	Version int64
}

type MemorySecretService struct {
	mu sync.RWMutex
	m  map[string]entry
}

func NewMemorySecretService(seed map[string]string) *MemorySecretService {
	m := map[string]entry{}
	for k, v := range seed {
		m[k] = entry{Value: v, Version: 1}
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

func (s *MemorySecretService) PutSecret(ctx context.Context, key, value string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.m[key]
	e.Version++
	if e.Version == 1 {
		e.Version = 1
	}
	e.Value = value
	s.m[key] = e
	return e.Version, nil
}
