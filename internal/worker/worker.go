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

	trigger := func(runCtx context.Context) error {
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

	if cfg.WorkerRunNow {
		if err := trigger(ctx); err != nil {
			return err
		}
	}

	runner := scheduler.Runner{
		Interval: cfg.ScanInterval,
		Key:      "scan:" + cfg.Provider,
		Trigger:  trigger,
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		err := runner.Start(runCtx)
		if err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

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
