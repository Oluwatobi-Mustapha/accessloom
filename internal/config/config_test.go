package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("IDENTRAIL_HTTP_ADDR", "")
	t.Setenv("IDENTRAIL_LOG_LEVEL", "")
	t.Setenv("IDENTRAIL_PROVIDER", "")
	t.Setenv("IDENTRAIL_SERVICE_NAME", "")
	t.Setenv("IDENTRAIL_DATABASE_URL", "")
	t.Setenv("IDENTRAIL_AWS_FIXTURES", "")
	t.Setenv("IDENTRAIL_SCAN_INTERVAL", "")
	t.Setenv("IDENTRAIL_WORKER_RUN_NOW", "")
	t.Setenv("IDENTRAIL_API_KEYS", "")
	t.Setenv("IDENTRAIL_WRITE_API_KEYS", "")
	t.Setenv("IDENTRAIL_API_KEY_SCOPES", "")
	t.Setenv("IDENTRAIL_RATE_LIMIT_RPM", "")
	t.Setenv("IDENTRAIL_RATE_LIMIT_BURST", "")
	t.Setenv("IDENTRAIL_RUN_MIGRATIONS", "")
	t.Setenv("IDENTRAIL_MIGRATIONS_DIR", "")
	t.Setenv("IDENTRAIL_AUDIT_LOG_FILE", "")

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
	if cfg.ScanInterval != defaultScanInterval {
		t.Fatalf("expected default scan interval %v, got %v", defaultScanInterval, cfg.ScanInterval)
	}
	if !cfg.WorkerRunNow {
		t.Fatal("expected default worker run now true")
	}
	if len(cfg.APIKeys) != 0 {
		t.Fatalf("expected no api keys by default, got %+v", cfg.APIKeys)
	}
	if len(cfg.WriteAPIKeys) != 0 {
		t.Fatalf("expected no write api keys by default, got %+v", cfg.WriteAPIKeys)
	}
	if len(cfg.APIKeyScopes) != 0 {
		t.Fatalf("expected no scoped keys by default, got %+v", cfg.APIKeyScopes)
	}
	if cfg.RateLimitRPM != 120 || cfg.RateLimitBurst != 20 {
		t.Fatalf("unexpected default rate limit settings: rpm=%d burst=%d", cfg.RateLimitRPM, cfg.RateLimitBurst)
	}
	if !cfg.RunMigrations {
		t.Fatal("expected run migrations true")
	}
	if cfg.MigrationsDir != "migrations" {
		t.Fatalf("unexpected migrations dir: %q", cfg.MigrationsDir)
	}
	if cfg.AuditLogFile != "" {
		t.Fatalf("expected empty audit log file, got %q", cfg.AuditLogFile)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("IDENTRAIL_HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("IDENTRAIL_LOG_LEVEL", "DEBUG")
	t.Setenv("IDENTRAIL_PROVIDER", "AWS")
	t.Setenv("IDENTRAIL_SERVICE_NAME", "identrail-dev")
	t.Setenv("IDENTRAIL_DATABASE_URL", "postgres://example")
	t.Setenv("IDENTRAIL_AWS_FIXTURES", "fixtures/a.json,fixtures/b.json")
	t.Setenv("IDENTRAIL_SCAN_INTERVAL", "30m")
	t.Setenv("IDENTRAIL_WORKER_RUN_NOW", "false")
	t.Setenv("IDENTRAIL_API_KEYS", "key1,key2")
	t.Setenv("IDENTRAIL_WRITE_API_KEYS", "key2")
	t.Setenv("IDENTRAIL_API_KEY_SCOPES", "key1:read;key2:read,write")
	t.Setenv("IDENTRAIL_RATE_LIMIT_RPM", "300")
	t.Setenv("IDENTRAIL_RATE_LIMIT_BURST", "50")
	t.Setenv("IDENTRAIL_RUN_MIGRATIONS", "false")
	t.Setenv("IDENTRAIL_MIGRATIONS_DIR", "db/migrations")
	t.Setenv("IDENTRAIL_AUDIT_LOG_FILE", "/tmp/audit.log")

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
	if cfg.ScanInterval != 30*time.Minute {
		t.Fatalf("unexpected scan interval: %v", cfg.ScanInterval)
	}
	if cfg.WorkerRunNow {
		t.Fatal("expected worker run now false")
	}
	if len(cfg.APIKeys) != 2 || cfg.APIKeys[0] != "key1" || cfg.APIKeys[1] != "key2" {
		t.Fatalf("unexpected api keys: %+v", cfg.APIKeys)
	}
	if len(cfg.WriteAPIKeys) != 1 || cfg.WriteAPIKeys[0] != "key2" {
		t.Fatalf("unexpected write api keys: %+v", cfg.WriteAPIKeys)
	}
	if len(cfg.APIKeyScopes) != 2 || cfg.APIKeyScopes["key1"][0] != "read" || len(cfg.APIKeyScopes["key2"]) != 2 {
		t.Fatalf("unexpected key scopes: %+v", cfg.APIKeyScopes)
	}
	if cfg.RateLimitRPM != 300 || cfg.RateLimitBurst != 50 {
		t.Fatalf("unexpected rate limit settings: rpm=%d burst=%d", cfg.RateLimitRPM, cfg.RateLimitBurst)
	}
	if cfg.RunMigrations {
		t.Fatal("expected run migrations false")
	}
	if cfg.MigrationsDir != "db/migrations" {
		t.Fatalf("unexpected migrations dir: %q", cfg.MigrationsDir)
	}
	if cfg.AuditLogFile != "/tmp/audit.log" {
		t.Fatalf("unexpected audit log file: %q", cfg.AuditLogFile)
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

func TestParseDuration(t *testing.T) {
	if got := parseDuration("10m", defaultScanInterval); got != 10*time.Minute {
		t.Fatalf("expected 10m, got %v", got)
	}
	if got := parseDuration("bad", defaultScanInterval); got != defaultScanInterval {
		t.Fatalf("expected fallback, got %v", got)
	}
}

func TestParseBool(t *testing.T) {
	if got := parseBool("true", false); !got {
		t.Fatal("expected true")
	}
	if got := parseBool("bad", true); !got {
		t.Fatal("expected fallback true")
	}
}

func TestParseInt(t *testing.T) {
	if got := parseInt("25", 1); got != 25 {
		t.Fatalf("expected 25, got %d", got)
	}
	if got := parseInt("0", 7); got != 7 {
		t.Fatalf("expected fallback 7, got %d", got)
	}
	if got := parseInt("bad", 9); got != 9 {
		t.Fatalf("expected fallback 9, got %d", got)
	}
}

func TestParseKeyScopes(t *testing.T) {
	scopes := parseKeyScopes("key1:read;key2:read,write;invalid;:missing")
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scoped keys, got %d", len(scopes))
	}
	if len(scopes["key2"]) != 2 {
		t.Fatalf("expected key2 to have 2 scopes, got %+v", scopes["key2"])
	}
}
