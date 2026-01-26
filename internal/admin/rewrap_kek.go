package admin

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/timgst1/glass/internal/crypto/envelope"
)

type RewrapKEKOptions struct {
	FromKEKID string
	ToKEKID   string
	BatchSize int
	DryRun    bool
}

type RewrapKEKResult struct {
	Matched int
	Updated int
}

func RewrapKEK(ctx context.Context, db *sql.DB, env *envelope.Envelope, opt RewrapKEKOptions) (RewrapKEKResult, error) {
	if db == nil {
		return RewrapKEKResult{}, fmt.Errorf("db is nil")
	}
	if env == nil {
		return RewrapKEKResult{}, fmt.Errorf("envelope is nil")
	}
	if opt.FromKEKID == "" {
		return RewrapKEKResult{}, fmt.Errorf("FromKEKID is empty")
	}
	if opt.ToKEKID == "" {
		return RewrapKEKResult{}, fmt.Errorf("ToKEKID is empty")
	}
	if opt.FromKEKID == opt.ToKEKID {
		return RewrapKEKResult{}, fmt.Errorf("from and to KEK IDs are equal (%q)", opt.FromKEKID)
	}
	if opt.BatchSize <= 0 {
		opt.BatchSize = 500
	}

	var total int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM secrets WHERE enc=1 AND kek_id=?`,
		opt.FromKEKID,
	).Scan(&total); err != nil {
		return RewrapKEKResult{}, err
	}

	// Dry-run: just report
	if opt.DryRun {
		return RewrapKEKResult{Matched: total, Updated: 0}, nil
	}

	res := RewrapKEKResult{Matched: total, Updated: 0}

	// Cursor for stable pagination
	lastKey := ""
	var lastVer int64 = 0

	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return res, err
		}

		rows, err := tx.QueryContext(ctx, `
SELECT key, version, wrapped_dek, wrap_nonce, kek_id
FROM secrets
WHERE enc=1
  AND kek_id=?
  AND (key > ? OR (key = ? AND version > ?))
ORDER BY key, version
LIMIT ?;`,
			opt.FromKEKID, lastKey, lastKey, lastVer, opt.BatchSize,
		)
		if err != nil {
			_ = tx.Rollback()
			return res, err
		}

		type row struct {
			Key        string
			Version    int64
			WrappedDEK string
			WrapNonce  string
			KEKID      string
		}
		batch := make([]row, 0, opt.BatchSize)

		for rows.Next() {
			var r row
			if err := rows.Scan(&r.Key, &r.Version, &r.WrappedDEK, &r.WrapNonce, &r.KEKID); err != nil {
				rows.Close()
				_ = tx.Rollback()
				return res, err
			}
			batch = append(batch, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			_ = tx.Rollback()
			return res, err
		}
		_ = rows.Close()

		if len(batch) == 0 {
			_ = tx.Commit()
			break
		}

		for _, r := range batch {
			ev := envelope.EncryptedValue{
				Enc:        1,
				KekID:      r.KEKID,
				WrappedDEK: r.WrappedDEK,
				WrapNonce:  r.WrapNonce,
			}

			newEV, err := env.RewrapDEK(r.Key, r.Version, ev, opt.ToKEKID)
			if err != nil {
				_ = tx.Rollback()
				return res, fmt.Errorf("rewrap %s@%d: %w", r.Key, r.Version, err)
			}

			_, err = tx.ExecContext(ctx, `
UPDATE secrets
SET wrapped_dek=?, wrap_nonce=?, kek_id=?
WHERE key=? AND version=?;`,
				newEV.WrappedDEK, newEV.WrapNonce, newEV.KekID, r.Key, r.Version,
			)
			if err != nil {
				_ = tx.Rollback()
				return res, err
			}

			res.Updated++
			lastKey = r.Key
			lastVer = r.Version
		}

		if err := tx.Commit(); err != nil {
			_ = tx.Rollback()
			return res, err
		}
	}

	return res, nil
}
