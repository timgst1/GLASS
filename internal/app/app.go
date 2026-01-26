package app

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/timgst1/glass/internal/authn"
	"github.com/timgst1/glass/internal/authz"
	"github.com/timgst1/glass/internal/crypto/envelope"
	"github.com/timgst1/glass/internal/httpapi"
	"github.com/timgst1/glass/internal/policy"
	"github.com/timgst1/glass/internal/service"
	"github.com/timgst1/glass/internal/storage/sqlite"
)

type Runtime struct {
	Server        *http.Server
	PolicyManager *policy.Manager
	DB            *sql.DB
}

func Build(ctx context.Context, cfg Config) (*Runtime, error) {
	var a authn.Authenticator

	switch cfg.AUTH_MODE {
	case "bearer":
		bearer, err := authn.NewBearerFromFile(cfg.AUTH_TOKEN_FILE)
		if err != nil {
			return nil, err
		}
		a = bearer
	case "noop":
		a = authn.Noop{}
	default:
		return nil, fmt.Errorf("invalid AUTH_MODE: %q", cfg.AUTH_MODE)
	}

	pm := policy.NewManager(cfg.POLICY_FILE)
	if err := pm.Start(ctx); err != nil {
		return nil, err
	}

	var db *sql.DB
	var secretSvc service.SecretService

	switch cfg.STORAGE_BACKEND {
	case "sqlite":
		d, err := sqlite.Open(cfg.SQLITE_PATH)
		if err != nil {
			return nil, err
		}
		if err := sqlite.Migrate(d); err != nil {
			_ = d.Close()
			return nil, err
		}
		db = d

		var enc *envelope.Envelope
		if cfg.ENCRYPTION_MODE == "envelope" {
			kr, err := envelope.LoadKeyring(cfg.KEK_DIR, cfg.ACTIVE_KEK_ID)
			if err != nil {
				_ = d.Close()
				return nil, err
			}
			enc = envelope.New(kr)
		}

		secretSvc = service.NewSQLiteSecretService(db, enc)

	case "memory":
		secretSvc = service.NewMemorySecretService(map[string]string{"demo": "hello"})

	default:
		return nil, fmt.Errorf("invalid STORAGE_BACKEND: %q", cfg.STORAGE_BACKEND)
	}

	az := authz.NewRuntimeAuthorizer(pm)
	secretSvc = service.NewSecuredSecretService(secretSvc, az)

	h := httpapi.NewRouter(httpapi.Deps{
		SecretService: secretSvc,
		Authenticator: a,
	})

	srv := BuildServer(cfg, h)

	return &Runtime{
		Server:        srv,
		PolicyManager: pm,
		DB:            db,
	}, nil
}

func BuildServer(cfg Config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:         cfg.HTTP_ADDR,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}
