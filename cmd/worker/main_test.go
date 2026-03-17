package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestRunCallsWorkerRuntime(t *testing.T) {
	origLoadConfig := loadConfig
	origWorkerRun := workerRun
	t.Cleanup(func() {
		loadConfig = origLoadConfig
		workerRun = origWorkerRun
	})

	loadConfig = func() config.Config { return config.Config{Provider: "aws"} }
	var called bool
	workerRun = func(_ context.Context, cfg config.Config, sigCh <-chan os.Signal) error {
		called = true
		if cfg.Provider != "aws" {
			t.Fatalf("unexpected provider %q", cfg.Provider)
		}
		if sigCh == nil {
			t.Fatal("expected signal channel")
		}
		return nil
	}

	if err := run(context.Background(), make(chan os.Signal, 1)); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !called {
		t.Fatal("expected worker runtime to be called")
	}
}

func TestRunPropagatesError(t *testing.T) {
	origLoadConfig := loadConfig
	origWorkerRun := workerRun
	t.Cleanup(func() {
		loadConfig = origLoadConfig
		workerRun = origWorkerRun
	})

	loadConfig = func() config.Config { return config.Config{} }
	workerRun = func(context.Context, config.Config, <-chan os.Signal) error {
		return errors.New("runtime failed")
	}

	if err := run(context.Background(), make(chan os.Signal, 1)); err == nil {
		t.Fatal("expected error")
	}
}
