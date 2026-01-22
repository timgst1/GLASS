package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/timgst1/glass/internal/authn"
)

type SQLiteSecretService struct {
	db *sql.DB
}

func NewSQLiteSecretService(db *sql.DB) *SQLiteSecretService {
	return &SQLiteSecretService{db: db}
}

func (s *SQLiteSecretService) GetSecret(ctx context.Context, key string) (string, error) {
	const q = `SELECT value FROM secrets WHERE key = ? ORDER BY version DESC LIMIT 1`
	var v string
	err := s.db.QueryRowContext(ctx, q, key).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return v, nil
}

func (s *SQLiteSecretService) GetSecretMeta(ctx context.Context, key string) (SecretMeta, error) {
	const q = `SELECT key, version, created_at, created_by FROM secrets WHERE key = ? ORDER BY version DESC LIMIT 1`

	var (
		k         string
		version   int64
		createdAt string
		createdBy string
	)

	err := s.db.QueryRowContext(ctx, q, key).Scan(&k, &version, &createdAt, &createdBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SecretMeta{}, ErrNotFound
		}
		return SecretMeta{}, err
	}

	return SecretMeta{
		Key:       k,
		Version:   version,
		CreatedAt: createdAt,
		CreatedBy: createdBy,
	}, nil
}

func (s *SQLiteSecretService) ListSecrets(ctx context.Context, prefix string) ([]SecretItem, error) {
	//Latest version per key for a prefix
	const q = `
SELECT s.key, s.value, s.version, s.created_at, s.created_by
FROM secrets s
JOIN (
    SELECT key, MAX(version) AS max_version
    FROM secrets
    WHERE key LIKE ?
    GROUP BY key
) m ON s.key = m.key AND s.version = m.max_version
ORDER BY s.key;
`
	like := prefix + "%"

	rows, err := s.db.QueryContext(ctx, q, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SecretItem{}
	for rows.Next() {
		var it SecretItem
		if err := rows.Scan(&it.Key, &it.Value, &it.Version, &it.CreatedAt, &it.CreatedBy); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (s *SQLiteSecretService) PutSecret(ctx context.Context, key, value string) (int64, error) {
	sub, _ := authn.SubjectFromContext(ctx)
	createdBy := sub.Kind + ":" + sub.Name
	if createdBy == ":" {
		createdBy = "unknown"
	}

	//Retry bei Versions-Kollision (UNIQUE constraint) unter Concurrent Writes
	for attempt := 0; attempt < 3; attempt++ {
		tx, err := s.db.BeginTx(ctx, nil)

		if err != nil {
			return 0, err
		}

		var cur sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT MAX(version) FROM secrets WHERE key = ?`, key).Scan(&cur)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}

		next := int64(1)
		if cur.Valid {
			next = cur.Int64 + 1
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO secrets(key, version, value, created_by) VALUES(?, ?, ?, ?)`,
			key, next, value, createdBy,
		)
		if err != nil {
			_ = tx.Rollback()
			//Versions-Kontrolle -> retry
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				continue
			}
			return 0, err
		}

		if err := tx.Commit(); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		return next, nil
	}

	return 0, fmt.Errorf("write conflict: could not allocate new version")
}
