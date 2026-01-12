package service

import (
	"context"
	"sync"
)

type MemorySecretService struct {
	mu sync.RWMutex
	m  map[string]string
}

func NewMemorySecretService(seed map[string]string) *MemorySecretService {
	if seed == nil {
		seed = map[string]string{}
	}
	return &MemorySecretService{m: seed}
}

func (s *MemorySecretService) GetSecret(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
