package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/timgst1/glass/internal/app"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "rewrap-kek":
			if err := runRewrapKek(os.Args[2:]); err != nil {
				log.Fatal(err)
			}
			return
		default:
			log.Fatalf("unkown command: %s (supported: rewrap-kek)", os.Args[1])
		}
	}
	if err := runServer(); err != nil {
		log.Fatal(err)
	}
}

func runServer() error {
	cfg, err := app.LoadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rt, err := app.Build(ctx, cfg)
	if err != nil {
		return err
	}
	if rt.DB != nil {
		defer rt.DB.Close()
	}

	// Shutdown on signal
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = rt.Server.Shutdown(shutdownCtx)
	}()

	err = rt.Server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
