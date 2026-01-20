package service

import (
	"context"
	"errors"
)

var (
	ErrNotFound  = errors.New("secret not found")
	ErrForbidden = errors.New("forbidden")
)

type SecretService interface {
	GetSecret(ctx context.Context, key string) (string, error)
	PutSecret(ctx context.Context, key, value string) (int64, error)
}
