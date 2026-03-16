package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/api"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/runtime"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"go.uber.org/zap"
)

// Bootstrap contains dependencies for the HTTP API runtime.
type Bootstrap struct {
	Logger        *zap.Logger
	Metrics       *telemetry.Metrics
	Router        http.Handler
	TraceShutdown func(context.Context) error
	StoreClose    func() error
	AuditClose    func() error
}

// NewBootstrap initializes logger, metrics, tracing, and router in one place.
func NewBootstrap(ctx context.Context, cfg config.Config) (Bootstrap, error) {
	logger, err := telemetry.NewLogger(cfg.LogLevel)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initialize logger: %w", err)
	}
	if err := config.ValidateSecurity(cfg); err != nil {
		_ = logger.Sync()
		return Bootstrap{}, fmt.Errorf("validate security config: %w", err)
	}
	for _, warning := range config.SecurityWarnings(cfg) {
		logger.Warn("security configuration warning", telemetry.String("detail", warning))
	}

	metrics := telemetry.NewMetrics()
	traceShutdown, err := telemetry.SetupTracing(ctx, cfg.ServiceName)
	if err != nil {
		_ = logger.Sync()
		return Bootstrap{}, fmt.Errorf("initialize tracing: %w", err)
	}

	svc, closeStore, err := runtime.BuildScanService(cfg)
	if err != nil {
		_ = logger.Sync()
		return Bootstrap{}, fmt.Errorf("initialize runtime: %w", err)
	}
	svc.OnAlertError = func(alertErr error) {
		logger.Warn("scan alert delivery failed", telemetry.ZapError(alertErr))
	}
	auditSink := api.AuditSink(api.NopAuditSink{})
	auditClose := func() error { return nil }
	if cfg.AuditLogFile != "" {
		fileSink, sinkErr := api.NewFileAuditSink(cfg.AuditLogFile)
		if sinkErr != nil {
			_ = closeStore()
			_ = logger.Sync()
			return Bootstrap{}, fmt.Errorf("initialize audit sink: %w", sinkErr)
		}
		auditSink = fileSink
		auditClose = fileSink.Close
	}
	router := api.NewRouter(logger, metrics, svc, api.RouterOptions{
		APIKeys:        cfg.APIKeys,
		WriteAPIKeys:   cfg.WriteAPIKeys,
		APIKeyScopes:   cfg.APIKeyScopes,
		RateLimitRPM:   cfg.RateLimitRPM,
		RateLimitBurst: cfg.RateLimitBurst,
		AuditSink:      auditSink,
	})
	return Bootstrap{
		Logger:        logger,
		Metrics:       metrics,
		Router:        router,
		TraceShutdown: traceShutdown,
		StoreClose:    closeStore,
		AuditClose:    auditClose,
	}, nil
}

// NewHTTPServer builds an http.Server with hardened defaults.
func NewHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Run starts the API runtime and gracefully shuts down on signal or context cancellation.
func Run(ctx context.Context, cfg config.Config, signals <-chan os.Signal) error {
	bootstrap, err := NewBootstrap(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = bootstrap.Logger.Sync() }()
	defer func() {
		if bootstrap.StoreClose != nil {
			_ = bootstrap.StoreClose()
		}
	}()
	defer func() {
		if bootstrap.AuditClose != nil {
			_ = bootstrap.AuditClose()
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = bootstrap.TraceShutdown(shutdownCtx)
	}()

	srv := NewHTTPServer(cfg, bootstrap.Router)
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			errCh <- nil
			return
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		bootstrap.Logger.Info("shutdown requested by context")
	case <-signals:
		bootstrap.Logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	return nil
}
