package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/timgst1/glass/internal/storage/sqlite"
)

func newTestSQLiteSecretService(t *testing.T) *SQLiteSecretService {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.sqlite")

	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := sqlite.Migrate(db); err != nil {
		t.Fatalf("sqlite.Migrate: %v", err)
	}

	return NewSQLiteSecretService(db)
}

func TestSQLiteSecretService_PutGet_Versioning(t *testing.T) {
	svc := newTestSQLiteSecretService(t)
	ctx := context.Background()

	v1, err := svc.PutSecret(ctx, "demo", "hello")
	if err != nil {
		t.Fatalf("PutSecret v1: %v", err)
	}
	if v1 != 1 {
		t.Fatalf("expected version 1, got %d", v1)
	}

	got, err := svc.GetSecret(ctx, "demo")
	if err != nil {
		t.Fatalf("GetSecret aftter v1: %v", err)
	}
	if got != "hello" {
		t.Fatalf("expected value=hello, got %q", got)
	}

	v2, err := svc.PutSecret(ctx, "demo", "world")
	if err != nil {
		t.Fatalf("PutSecret v2: %v", err)
	}
	if v2 != 2 {
		t.Fatalf("expected version 2, got %d", v2)
	}

	got, err = svc.GetSecret(ctx, "demo")
	if err != nil {
		t.Fatalf("GetSecret after v2: %v", err)
	}
	if got != "world" {
		t.Fatalf("expected value=world, got  %q", got)
	}
}

func TestSQLiteSecretService_GetSecret_NotFound(t *testing.T) {
	svc := newTestSQLiteSecretService(t)
	ctx := context.Background()

	_, err := svc.GetSecret(ctx, "missing")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteSecretService_VersioningIsPerKey(t *testing.T) {
	svc := newTestSQLiteSecretService(t)
	ctx := context.Background()

	va, err := svc.PutSecret(ctx, "a", "x")
	if err != nil {
		t.Fatalf("PutSecret a: %v", err)
	}
	if va != 1 {
		t.Fatalf("expected a version 1, got %d", va)
	}

	vb, err := svc.PutSecret(ctx, "b", "y")
	if err != nil {
		t.Fatalf("PutSecret b: %v", err)
	}
	if vb != 1 {
		t.Fatalf("expected b version 1, got %d", vb)
	}
}
