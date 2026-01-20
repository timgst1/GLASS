package service

import (
	"context"
	"fmt"

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

func (s *SecuredSecretService) GetSecret(ctx context.Context, key string) (string, error) {
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
