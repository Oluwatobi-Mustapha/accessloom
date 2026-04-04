package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/api"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/runtime"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
)

const (
	defaultWorkerTriggerMaxAttempts = 3
	defaultWorkerRetryBackoff       = 2 * time.Second
	defaultWorkerQueueMaxAttempts   = 1
)

// Run starts the scheduled worker loop and exits on signal or context cancellation.
func Run(ctx context.Context, cfg config.Config, signals <-chan os.Signal) error {
	logger, err := telemetry.NewLogger(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()
	if err := config.ValidateSecurity(cfg); err != nil {
		return fmt.Errorf("validate security config: %w", err)
	}
	for _, warning := range config.SecurityWarnings(cfg) {
		logger.Warn("security configuration warning", telemetry.String("detail", warning))
	}

	traceShutdown, err := telemetry.SetupTracing(ctx, cfg.ServiceName+"-worker")
	if err != nil {
		return fmt.Errorf("initialize tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = traceShutdown(shutdownCtx)
	}()

	svc, closeStore, err := runtime.BuildScanService(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = closeStore() }()
	svc.OnAlertError = func(alertErr error) {
		logger.Warn("scan alert delivery failed", telemetry.ZapError(alertErr))
	}

	cloudTrigger := func(runCtx context.Context) error {
		result, runErr := svc.RunScan(runCtx)
		if runErr != nil {
			if errors.Is(runErr, api.ErrScanInProgress) {
				logger.Info("scan skipped because another run is in progress")
				return nil
			}
			logger.Error("scheduled scan failed", telemetry.ZapError(runErr))
			return runErr
		}
		logger.Info("scheduled scan completed", telemetry.String("scan_id", result.Scan.ID))
		return nil
	}
	repoTrigger := func(runCtx context.Context) error {
		failures := 0
		for _, target := range cfg.WorkerRepoScanTargets {
			repoRun, runErr := svc.RunRepoScanPersisted(runCtx, api.RepoScanRequest{
				Repository:   target,
				HistoryLimit: cfg.WorkerRepoScanHistory,
				MaxFindings:  cfg.WorkerRepoScanFindings,
			})
			if runErr != nil {
				if errors.Is(runErr, api.ErrRepoScanInProgress) {
					logger.Info("repo scan skipped because another run is in progress", telemetry.String("repository", target))
					continue
				}
				failures++
				logger.Error("scheduled repo scan failed", telemetry.String("repository", target), telemetry.ZapError(runErr))
				continue
			}
			logger.Info(
				"scheduled repo scan completed",
				telemetry.String("repository", target),
				telemetry.String("repo_scan_id", repoRun.RepoScan.ID),
			)
		}
		if failures > 0 {
			return fmt.Errorf("repo scan batch failed for %d target(s)", failures)
		}
		return nil
	}
	queueBatchSize := cfg.WorkerAPIJobQueueBatchSize
	if queueBatchSize <= 0 {
		queueBatchSize = 1
	}
	apiQueueTrigger := func(runCtx context.Context) error {
		for i := 0; i < queueBatchSize; i++ {
			processed, processErr := svc.ProcessNextQueuedScan(runCtx)
			if processErr != nil {
				logger.Error("queued scan processing failed", telemetry.ZapError(processErr))
				continue
			}
			if !processed {
				break
			}
		}
		for i := 0; i < queueBatchSize; i++ {
			processed, processErr := svc.ProcessNextQueuedRepoScan(runCtx)
			if processErr != nil {
				logger.Error("queued repo scan processing failed", telemetry.ZapError(processErr))
				continue
			}
			if !processed {
				break
			}
		}
		return nil
	}

	type scheduledRunner struct {
		name   string
		runNow bool
		runner scheduler.Runner
	}

	runners := []scheduledRunner{{
		name:   "cloud",
		runNow: cfg.WorkerRunNow,
		runner: scheduler.Runner{
			Interval:     cfg.ScanInterval,
			Key:          "scan:" + cfg.Provider,
			Trigger:      cloudTrigger,
			MaxAttempts:  defaultWorkerTriggerMaxAttempts,
			RetryBackoff: defaultWorkerRetryBackoff,
			OnDeadLetter: func(_ context.Context, err error) {
				logger.Error("cloud trigger exhausted retries; dead-letter event emitted", telemetry.ZapError(err))
			},
		},
	}}
	if cfg.WorkerRepoScanEnabled {
		runners = append(runners, scheduledRunner{
			name:   "repo",
			runNow: cfg.WorkerRepoScanRunNow,
			runner: scheduler.Runner{
				Interval:     cfg.WorkerRepoScanInterval,
				Key:          "repo-scan",
				Trigger:      repoTrigger,
				MaxAttempts:  defaultWorkerTriggerMaxAttempts,
				RetryBackoff: defaultWorkerRetryBackoff,
				OnDeadLetter: func(_ context.Context, err error) {
					logger.Error("repo trigger exhausted retries; dead-letter event emitted", telemetry.ZapError(err))
				},
			},
		})
	}
	if cfg.WorkerAPIJobQueueEnabled {
		runners = append(runners, scheduledRunner{
			name:   "api-queue",
			runNow: false,
			runner: scheduler.Runner{
				Interval:     cfg.WorkerAPIJobQueueInterval,
				Key:          "api-job-queue",
				Trigger:      apiQueueTrigger,
				MaxAttempts:  defaultWorkerQueueMaxAttempts,
				RetryBackoff: defaultWorkerRetryBackoff,
				OnDeadLetter: func(_ context.Context, err error) {
					logger.Error("api job queue trigger exhausted retries; dead-letter event emitted", telemetry.ZapError(err))
				},
			},
		})
	}

	for _, item := range runners {
		if !item.runNow {
			continue
		}
		if err := item.runner.RunOnce(ctx); err != nil {
			return fmt.Errorf("%s startup run: %w", item.name, err)
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(runners))
	for _, item := range runners {
		runSpec := item
		go func() {
			err := runSpec.runner.Start(runCtx)
			if err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("%s runner failed: %w", runSpec.name, err)
				return
			}
			errCh <- nil
		}()
	}

	select {
	case <-ctx.Done():
		cancel()
		return nil
	case <-signals:
		cancel()
		return nil
	case runErr := <-errCh:
		return runErr
	}
}
