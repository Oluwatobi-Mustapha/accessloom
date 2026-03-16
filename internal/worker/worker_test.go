package worker

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestRunWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.Config{
		LogLevel:       "info",
		ServiceName:    "identrail-test",
		Provider:       "aws",
		ScanInterval:   10 * time.Millisecond,
		WorkerRunNow:   false,
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunFailsWhenStartupScanCannotReadFixtures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		LogLevel:       "info",
		ServiceName:    "identrail-test",
		Provider:       "aws",
		ScanInterval:   10 * time.Millisecond,
		WorkerRunNow:   true,
		AWSFixturePath: []string{"/path/does/not/exist.json"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected startup scan error")
	}
}

func TestRunFailsWithInvalidStoreConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		LogLevel:       "info",
		ServiceName:    "identrail-test",
		Provider:       "aws",
		ScanInterval:   10 * time.Millisecond,
		WorkerRunNow:   false,
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
		DatabaseURL:    "postgres://user:pass@127.0.0.1:1/identrail?sslmode=disable&connect_timeout=1",
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected store initialization error")
	}
}

func TestRunFailsWithInvalidSecurityConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		LogLevel:       "info",
		ServiceName:    "identrail-test",
		Provider:       "aws",
		ScanInterval:   10 * time.Millisecond,
		WorkerRunNow:   false,
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
		APIKeys:        []string{"reader"},
		WriteAPIKeys:   []string{"writer"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected security validation error")
	}
}
