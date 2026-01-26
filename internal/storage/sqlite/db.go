package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	// pragmas via DSN
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func Migrate(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS secrets (
	key TEXT NOT NULL,
	version INTEGER NOT NULL,

	-- When enc=0: value contains plaintext.
	-- When enc=1: value contains base64(ciphertext).
	value TEXT NOT NULL,

	enc INTEGER NOT NULL DEFAULT 0,
	value_nonce TEXT NOT NULL DEFAULT '',
	wrapped_dek TEXT NOT NULL DEFAULT '',
	wrap_nonce TEXT NOT NULL DEFAULT '',
	kek_id TEXT NOT NULL DEFAULT '',

	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
	created_by TEXT NOT NULL,
	PRIMARY KEY (key, version)
);

CREATE INDEX IF NOT EXISTS idx_secrets_key_version ON secrets(key, version DESC);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Backward-compatible upgrade for existing tables (adds missing columns).
	if err := ensureColumn(db, "secrets", "enc", "enc INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "secrets", "value_nonce", "value_nonce TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "secrets", "wrapped_dek", "wrapped_dek TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "secrets", "wrap_nonce", "wrap_nonce TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "secrets", "kek_id", "kek_id TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	return nil
}

func ensureColumn(db *sql.DB, table, col, ddl string) error {
	cols, err := tableColumns(db, table)
	if err != nil {
		return err
	}
	if cols[col] {
		return nil
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s;", table, ddl))
	return err
}

func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s);", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var (
			cid       int
			name      string
			type_     string
			notnull   int
			dfltValue *string
			pk        int
		)
		if err := rows.Scan(&cid, &name, &type_, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cols, nil
}
