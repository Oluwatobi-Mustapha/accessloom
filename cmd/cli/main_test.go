package main

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestRunCallsExecute(t *testing.T) {
	origLoadConfig := loadConfig
	origExecute := cliExecute
	t.Cleanup(func() {
		loadConfig = origLoadConfig
		cliExecute = origExecute
	})

	loadConfig = func() config.Config {
		return config.Config{Provider: "aws"}
	}
	var called bool
	cliExecute = func(cfg config.Config, args []string, out io.Writer) error {
		called = true
		if cfg.Provider != "aws" {
			t.Fatalf("unexpected provider %q", cfg.Provider)
		}
		if len(args) != 1 || args[0] != "scan" {
			t.Fatalf("unexpected args %+v", args)
		}
		if _, ok := out.(*bytes.Buffer); !ok {
			t.Fatalf("unexpected stdout type %T", out)
		}
		return nil
	}

	var stdout bytes.Buffer
	if err := run([]string{"scan"}, &stdout); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !called {
		t.Fatal("expected execute to be called")
	}
}

func TestRunPropagatesError(t *testing.T) {
	origLoadConfig := loadConfig
	origExecute := cliExecute
	t.Cleanup(func() {
		loadConfig = origLoadConfig
		cliExecute = origExecute
	})

	loadConfig = func() config.Config { return config.Config{} }
	cliExecute = func(config.Config, []string, io.Writer) error {
		return errors.New("boom")
	}

	var stdout bytes.Buffer
	if err := run([]string{"bad"}, &stdout); err == nil {
		t.Fatal("expected error")
	}
}
