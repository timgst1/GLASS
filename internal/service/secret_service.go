package service

import (
	"context"
	"errors"
)

var (
	ErrNotFound  = errors.New("secret not found")
	ErrForbidden = errors.New("forbidden")
)

type SecretMeta struct {
	Key       string
	Version   int64
	CreatedAt string
	CreatedBy string
}

type SecretItem struct {
	Key       string
	Value     string
	Version   int64
	CreatedAt string
	CreatedBy string
}

type SecretService interface {
	GetSecret(ctx context.Context, key string) (string, error)
	PutSecret(ctx context.Context, key, value string) (int64, error)

	GetSecretMeta(ctx context.Context, key string) (SecretMeta, error)
	ListSecrets(ctx context.Context, prefix string) ([]SecretItem, error)
}
