package service

import (
	"context"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/timgst1/glass/internal/crypto/envelope"
	"github.com/timgst1/glass/internal/storage/sqlite"
)

func newTestEnvelope(t *testing.T) *envelope.Envelope {
	t.Helper()

	dir := t.TempDir()
	// 32 bytes test key, base64 encoded in file
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 0x11
	}
	if err := os.WriteFile(filepath.Join(dir, "default"), []byte(base64.StdEncoding.EncodeToString(raw)), 0o600); err != nil {
		t.Fatalf("write kek: %v", err)
	}

	kr, err := envelope.LoadKeyring(dir, "default")
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	return envelope.New(kr)
}

func openTestDB(t *testing.T) *sql.DB {
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
	return db
}

func TestSQLiteSecretService_EncryptionAtRest(t *testing.T) {
	db := openTestDB(t)
	enc := newTestEnvelope(t)

	svc := NewSQLiteSecretService(db, enc)
	ctx := context.Background()

	_, err := svc.PutSecret(ctx, "demo", "super-secret")
	if err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	// Read back via service => plaintext
	got, err := svc.GetSecret(ctx, "demo")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "super-secret" {
		t.Fatalf("expected plaintext, got %q", got)
	}

	// Inspect DB row => should NOT contain plaintext
	var stored string
	var encFlag int
	err = db.QueryRowContext(ctx, `SELECT value, enc FROM secrets WHERE key=? ORDER BY version DESC LIMIT 1`, "demo").
		Scan(&stored, &encFlag)
	if err != nil {
		t.Fatalf("query db: %v", err)
	}
	if encFlag != 1 {
		t.Fatalf("expected enc=1, got %d", encFlag)
	}
	if stored == "super-secret" {
		t.Fatalf("expected ciphertext in DB, found plaintext")
	}
}
