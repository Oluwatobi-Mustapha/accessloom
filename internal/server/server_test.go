package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestNewBootstrap(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:     ":0",
		LogLevel:     "info",
		Provider:     "aws",
		ServiceName:  "identrail-test",
		APIKeys:      []string{"test-read"},
		WriteAPIKeys: []string{"test-read"},
	}
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
		APIKeys:      []string{"test-read"},
		WriteAPIKeys: []string{"test-read"},
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

func TestNewBootstrapWithAuditForwardSink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.Config{
		HTTPAddr:               ":0",
		LogLevel:               "info",
		Provider:               "aws",
		ServiceName:            "identrail-test",
		AuditForwardURL:        server.URL,
		AuditForwardTimeout:    2 * time.Second,
		AuditForwardHMACSecret: "secret",
		APIKeys:                []string{"test-read"},
		WriteAPIKeys:           []string{"test-read"},
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

func TestNewBootstrapInvalidAuditForwardConfig(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:        ":0",
		LogLevel:        "info",
		Provider:        "aws",
		ServiceName:     "identrail-test",
		AuditForwardURL: "http://example.com/events",
	}
	if _, err := NewBootstrap(context.Background(), cfg); err == nil {
		t.Fatal("expected invalid audit forward config error")
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

	cfg := config.Config{
		HTTPAddr:     ":0",
		LogLevel:     "info",
		Provider:     "aws",
		ServiceName:  "identrail-test",
		APIKeys:      []string{"test-read"},
		WriteAPIKeys: []string{"test-read"},
	}
	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected clean shutdown, got err: %v", err)
	}
}

func TestRunSignalRequested(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Config{
		HTTPAddr:     ":0",
		LogLevel:     "info",
		Provider:     "aws",
		ServiceName:  "identrail-test",
		APIKeys:      []string{"test-read"},
		WriteAPIKeys: []string{"test-read"},
	}

	sigCh := make(chan os.Signal, 1)
	sigCh <- os.Interrupt
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected clean shutdown on signal, got err: %v", err)
	}
}

func TestRunServerListenError(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:     "invalid-listen-address",
		LogLevel:     "info",
		Provider:     "aws",
		ServiceName:  "identrail-test",
		APIKeys:      []string{"test-read"},
		WriteAPIKeys: []string{"test-read"},
	}
	sigCh := make(chan os.Signal, 1)
	if err := Run(context.Background(), cfg, sigCh); err == nil {
		t.Fatal("expected listen error for invalid address")
	}
}

func TestNewBootstrapWithMultipleAuditSinks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.Config{
		HTTPAddr:               ":0",
		LogLevel:               "info",
		Provider:               "aws",
		ServiceName:            "identrail-test",
		AuditLogFile:           filepath.Join(t.TempDir(), "audit.log"),
		AuditForwardURL:        server.URL,
		AuditForwardTimeout:    2 * time.Second,
		AuditForwardHMACSecret: "secret",
		APIKeys:                []string{"test-read"},
		WriteAPIKeys:           []string{"test-read"},
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

func TestNewBootstrapInvalidOIDCVerifierConfig(t *testing.T) {
	cfg := config.Config{
		HTTPAddr:      ":0",
		LogLevel:      "info",
		Provider:      "aws",
		ServiceName:   "identrail-test",
		OIDCIssuerURL: "://bad-issuer",
		OIDCAudience:  "identrail-api",
		APIKeys:       []string{"test-read"},
		WriteAPIKeys:  []string{"test-read"},
	}
	if _, err := NewBootstrap(context.Background(), cfg); err == nil {
		t.Fatal("expected oidc verifier initialization error")
	}
}
