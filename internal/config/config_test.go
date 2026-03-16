package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("IDENTRAIL_HTTP_ADDR", "")
	t.Setenv("IDENTRAIL_LOG_LEVEL", "")
	t.Setenv("IDENTRAIL_PROVIDER", "")
	t.Setenv("IDENTRAIL_SERVICE_NAME", "")
	t.Setenv("IDENTRAIL_DATABASE_URL", "")
	t.Setenv("IDENTRAIL_AWS_FIXTURES", "")

	cfg := Load()
	if cfg.HTTPAddr != defaultHTTPAddr {
		t.Fatalf("expected default addr %q, got %q", defaultHTTPAddr, cfg.HTTPAddr)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Fatalf("expected default log level %q, got %q", defaultLogLevel, cfg.LogLevel)
	}
	if cfg.Provider != defaultProvider {
		t.Fatalf("expected default provider %q, got %q", defaultProvider, cfg.Provider)
	}
	if cfg.ServiceName != defaultServiceName {
		t.Fatalf("expected default service name %q, got %q", defaultServiceName, cfg.ServiceName)
	}
	if cfg.DatabaseURL != "" {
		t.Fatalf("expected empty database url, got %q", cfg.DatabaseURL)
	}
	if len(cfg.AWSFixturePath) != 2 {
		t.Fatalf("expected 2 default fixture paths, got %d", len(cfg.AWSFixturePath))
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("IDENTRAIL_HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("IDENTRAIL_LOG_LEVEL", "DEBUG")
	t.Setenv("IDENTRAIL_PROVIDER", "AWS")
	t.Setenv("IDENTRAIL_SERVICE_NAME", "identrail-dev")
	t.Setenv("IDENTRAIL_DATABASE_URL", "postgres://example")
	t.Setenv("IDENTRAIL_AWS_FIXTURES", "fixtures/a.json,fixtures/b.json")

	cfg := Load()
	if cfg.HTTPAddr != "127.0.0.1:9090" {
		t.Fatalf("unexpected addr: %q", cfg.HTTPAddr)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("unexpected log level: %q", cfg.LogLevel)
	}
	if cfg.Provider != "aws" {
		t.Fatalf("unexpected provider: %q", cfg.Provider)
	}
	if cfg.ServiceName != "identrail-dev" {
		t.Fatalf("unexpected service name: %q", cfg.ServiceName)
	}
	if cfg.DatabaseURL != "postgres://example" {
		t.Fatalf("unexpected database url: %q", cfg.DatabaseURL)
	}
	if len(cfg.AWSFixturePath) != 2 || cfg.AWSFixturePath[0] != "fixtures/a.json" || cfg.AWSFixturePath[1] != "fixtures/b.json" {
		t.Fatalf("unexpected fixture paths: %+v", cfg.AWSFixturePath)
	}
}

func TestGetEnvTrimmedFallback(t *testing.T) {
	key := "IDENTRAIL_TEST_ENV"
	_ = os.Unsetenv(key)

	if got := getEnv(key, "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}
	t.Setenv(key, "  actual  ")
	if got := getEnv(key, "fallback"); got != "actual" {
		t.Fatalf("expected trimmed value, got %q", got)
	}
}

func TestParseCommaSeparated(t *testing.T) {
	parsed := parseCommaSeparated("a,, b , ,c")
	if len(parsed) != 3 || parsed[0] != "a" || parsed[1] != "b" || parsed[2] != "c" {
		t.Fatalf("unexpected parsed values: %+v", parsed)
	}
}
