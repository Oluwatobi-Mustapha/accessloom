package worker

import (
	"context"
	"errors"
	"os"
	"strings"
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

func TestProcessAPIQueueBatchReturnsErrorWhenProcessingFails(t *testing.T) {
	scanErrors := 0
	repoErrors := 0
	err := processAPIQueueBatch(
		context.Background(),
		1,
		func(context.Context) (bool, error) { return false, errors.New("scan failure") },
		func(context.Context) (bool, error) { return false, errors.New("repo failure") },
		func(error) { scanErrors++ },
		func(error) { repoErrors++ },
	)
	if err == nil {
		t.Fatal("expected queue batch error")
	}
	if !strings.Contains(err.Error(), "api queue batch failed for 2 job(s)") {
		t.Fatalf("unexpected queue batch error: %v", err)
	}
	if scanErrors != 1 || repoErrors != 1 {
		t.Fatalf("expected one callback per processing error, got scan=%d repo=%d", scanErrors, repoErrors)
	}
}

func TestProcessAPIQueueBatchReturnsNilWhenNoFailures(t *testing.T) {
	err := processAPIQueueBatch(
		context.Background(),
		2,
		func(context.Context) (bool, error) { return false, nil },
		func(context.Context) (bool, error) { return false, nil },
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}
