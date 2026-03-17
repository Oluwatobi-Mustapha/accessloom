package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/worker"
)

var workerRun = worker.Run
var loadConfig = config.Load

func run(ctx context.Context, sigCh <-chan os.Signal) error {
	return workerRun(ctx, loadConfig(), sigCh)
}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := run(context.Background(), sigCh); err != nil {
		log.Fatalf("worker failed: %v", err)
	}
}
