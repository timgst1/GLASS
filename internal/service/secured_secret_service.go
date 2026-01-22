package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/timgst1/glass/internal/authn"
	"github.com/timgst1/glass/internal/authz"
)

type SecuredSecretService struct {
	inner SecretService
	az    authz.Authorizer
}

func NewSecuredSecretService(inner SecretService, az authz.Authorizer) *SecuredSecretService {
	return &SecuredSecretService{inner: inner, az: az}
}

func normalizeKey(k string) string {
	k = strings.TrimSpace(k)
	k = strings.TrimPrefix(k, "/")
	return k
}

func normalizePrefix(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/")
	return p
}

func (s *SecuredSecretService) GetSecret(ctx context.Context, key string) (string, error) {
	key = normalizeKey(key)

	sub, ok := authn.SubjectFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("%w: subject missing", ErrForbidden)
	}

	dec := s.az.Evaluate(sub, authz.ActionRead, key)
	if !dec.Allowed {
		return "", fmt.Errorf("%w: %s", ErrForbidden, dec.Reason)
	}

	return s.inner.GetSecret(ctx, key)
}

func (s *SecuredSecretService) PutSecret(ctx context.Context, key, value string) (int64, error) {
	key = normalizeKey(key)

	sub, ok := authn.SubjectFromContext(ctx)
	if !ok {
		return 0, fmt.Errorf("%w: subject missing", ErrForbidden)
	}

	dec := s.az.Evaluate(sub, authz.ActionWrite, key)
	if !dec.Allowed {
		return 0, fmt.Errorf("%w: %s", ErrForbidden, dec.Reason)
	}

	return s.inner.PutSecret(ctx, key, value)
}

func (s *SecuredSecretService) GetSecretMeta(ctx context.Context, key string) (SecretMeta, error) {
	key = normalizeKey(key)

	sub, ok := authn.SubjectFromContext(ctx)
	if !ok {
		return SecretMeta{}, fmt.Errorf("%w: subject missing", ErrForbidden)
	}

	// WICHTIG: AuthZ muss den gleichen key prüfen, der auch gelesen wird
	dec := s.az.Evaluate(sub, authz.ActionRead, key)
	if !dec.Allowed {
		return SecretMeta{}, fmt.Errorf("%w: %s", ErrForbidden, dec.Reason)
	}

	return s.inner.GetSecretMeta(ctx, key)
}

func (s *SecuredSecretService) ListSecrets(ctx context.Context, prefix string) ([]SecretItem, error) {
	prefix = normalizePrefix(prefix)

	sub, ok := authn.SubjectFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: subject missing", ErrForbidden)
	}

	dec := s.az.Evaluate(sub, authz.ActionList, prefix)
	if !dec.Allowed {
		return nil, fmt.Errorf("%w: %s", ErrForbidden, dec.Reason)
	}

	items, err := s.inner.ListSecrets(ctx, prefix)
	if err != nil {
		return nil, err
	}

	// Serverseitiges Filtern: nur read-allowed Keys zurückgeben
	out := make([]SecretItem, 0, len(items))
	for _, it := range items {
		rd := s.az.Evaluate(sub, authz.ActionRead, it.Key)
		if rd.Allowed {
			out = append(out, it)
		}
	}
	return out, nil
}
