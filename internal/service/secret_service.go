package service

import (
	"context"
	"errors"
)

var (
	ErrNotFound = errors.New("secret not found")
)

type SecretService interface {
	GetSecret(ctx context.Context, key string) (string, error)
}
