package main

import (
	"log"

	"github.com/timgst1/glass/internal/app"
)

func main() {
	cfg, err := app.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	h := app.BuildHTTPHandler(cfg)
	srv := app.BuildServer(cfg, h)

	log.Fatal(srv.ListenAndServe())
}
