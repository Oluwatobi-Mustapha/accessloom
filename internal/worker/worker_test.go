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
		APIKeys:        []string{"test-read"},
		WriteAPIKeys:   []string{"test-read"},
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
		APIKeys:        []string{"test-read"},
		WriteAPIKeys:   []string{"test-read"},
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
		APIKeys:        []string{"test-read"},
		WriteAPIKeys:   []string{"test-read"},
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

func TestRunWithCancelledContextAndRepoWorkerEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.Config{
		LogLevel:               "info",
		ServiceName:            "identrail-test",
		Provider:               "aws",
		ScanInterval:           10 * time.Millisecond,
		WorkerRunNow:           false,
		AWSFixturePath:         []string{"testdata/aws/role_with_policies.json"},
		APIKeys:                []string{"test-read"},
		WriteAPIKeys:           []string{"test-read"},
		RepoScanEnabled:        true,
		RepoScanAllowlist:      []string{"owner/repo"},
		WorkerRepoScanEnabled:  true,
		WorkerRepoScanRunNow:   false,
		WorkerRepoScanInterval: 15 * time.Minute,
		WorkerRepoScanTargets:  []string{"owner/repo"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunFailsWhenWorkerRepoStartupScanTargetIsInvalid(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		LogLevel:               "info",
		ServiceName:            "identrail-test",
		Provider:               "aws",
		ScanInterval:           10 * time.Millisecond,
		WorkerRunNow:           false,
		AWSFixturePath:         []string{"testdata/aws/role_with_policies.json"},
		APIKeys:                []string{"test-read"},
		WriteAPIKeys:           []string{"test-read"},
		RepoScanEnabled:        true,
		RepoScanAllowlist:      []string{"*"},
		WorkerRepoScanEnabled:  true,
		WorkerRepoScanRunNow:   true,
		WorkerRepoScanInterval: 15 * time.Minute,
		WorkerRepoScanTargets:  []string{"/path/does/not/exist"},
		WorkerRepoScanHistory:  1,
		WorkerRepoScanFindings: 10,
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err == nil {
		t.Fatal("expected worker repo startup scan error")
	}
}
