package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/timgst1/glass/internal/admin"
	"github.com/timgst1/glass/internal/crypto/envelope"
	"github.com/timgst1/glass/internal/storage/sqlite"
)

func runRewrapKek(args []string) error {
	fs := flag.NewFlagSet("rewrap-kek", flag.ContinueOnError)

	dbPath := fs.String("db", getenvDefault("SQLITE_PATH", "./data/glass.db"), "Path to sqlite db file")
	kekDir := fs.String("kek-dir", os.Getenv("KEK_DIR"), "Directory containing KEK files (mounted secret)")
	fromID := fs.String("from", "", "Source KEK id (current kek_id in DB rows) [required]")
	toID := fs.String("to", getenvDefault("ACTIVE_KEK_ID", "default"), "Target KEK id (new kek_id)")
	batch := fs.Int("batch", 500, "Batch size")
	dryRun := fs.Bool("dry-run", false, "Only report how many rows would change")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *kekDir == "" {
		return fmt.Errorf("--kek-dir (or env KEK_DIR) is required")
	}
	if *fromID == "" {
		return fmt.Errorf("--from is required")
	}
	if *toID == "" {
		return fmt.Errorf("--to is required")
	}
	if *fromID == *toID {
		return fmt.Errorf("--from and --to are equal (%q)", *fromID)
	}

	kr, err := envelope.LoadKeyring(*kekDir, *toID)
	if err != nil {
		return err
	}
	env := envelope.New(kr)

	db, err := sqlite.Open(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Ensure schema has the encryption columns
	if err := sqlite.Migrate(db); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := admin.RewrapKEK(ctx, db, env, admin.RewrapKEKOptions{
		FromKEKID: *fromID,
		ToKEKID:   *toID,
		BatchSize: *batch,
		DryRun:    *dryRun,
	})
	if err != nil {
		return err
	}

	if *dryRun {
		fmt.Printf("dry-run: would rewrap %d rows from kek_id=%q to kek_id=%q\n", res.Matched, *fromID, *toID)
		return nil
	}

	fmt.Printf("rewrap complete: matched=%d updated=%d from=%q to=%q\n", res.Matched, res.Updated, *fromID, *toID)
	return nil
}

func getenvDefault(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
