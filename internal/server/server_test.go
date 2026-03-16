package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestNewBootstrap(t *testing.T) {
	cfg := config.Config{HTTPAddr: ":0", LogLevel: "info", Provider: "aws", ServiceName: "identrail-test"}
	bootstrap, err := NewBootstrap(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if bootstrap.Logger == nil || bootstrap.Metrics == nil || bootstrap.Router == nil || bootstrap.TraceShutdown == nil || bootstrap.AuditClose == nil {
		t.Fatal("bootstrap dependencies must all be initialized")
	}
}

func TestNewBootstrapWithAuditFile(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:     ":0",
		LogLevel:     "info",
		Provider:     "aws",
		ServiceName:  "identrail-test",
		AuditLogFile: filepath.Join(t.TempDir(), "audit.log"),
	}
	bootstrap, err := NewBootstrap(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if bootstrap.AuditClose == nil {
		t.Fatal("expected audit close function")
	}
	if err := bootstrap.AuditClose(); err != nil {
		t.Fatalf("close audit sink: %v", err)
	}
}

func TestNewBootstrapAuditFileError(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:     ":0",
		LogLevel:     "info",
		Provider:     "aws",
		ServiceName:  "identrail-test",
		AuditLogFile: filepath.Join(t.TempDir(), "missing", "audit.log"),
	}
	if _, err := NewBootstrap(context.Background(), cfg); err == nil {
		t.Fatal("expected bootstrap error for invalid audit path")
	}
}

func TestNewBootstrapInvalidSecurityConfig(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:     ":0",
		LogLevel:     "info",
		Provider:     "aws",
		ServiceName:  "identrail-test",
		WriteAPIKeys: []string{"writer-only"},
		APIKeys:      []string{"reader-only"},
	}
	if _, err := NewBootstrap(context.Background(), cfg); err == nil {
		t.Fatal("expected security validation error")
	}
}

func TestNewHTTPServer(t *testing.T) {
	cfg := config.Config{HTTPAddr: ":9999"}
	srv := NewHTTPServer(cfg, nil)
	if srv.Addr != ":9999" {
		t.Fatalf("unexpected addr: %q", srv.Addr)
	}
	if srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatal("timeouts must be set")
	}
}

func TestRunCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.Config{HTTPAddr: ":0", LogLevel: "info", Provider: "aws", ServiceName: "identrail-test"}
	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected clean shutdown, got err: %v", err)
	}
}
