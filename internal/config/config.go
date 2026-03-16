package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPAddr     = ":8080"
	defaultLogLevel     = "info"
	defaultProvider     = "aws"
	defaultServiceName  = "identrail"
	defaultAWSFixtures  = "testdata/aws/role_with_policies.json,testdata/aws/role_with_urlencoded_trust.json"
	defaultScanInterval = 15 * time.Minute
)

// Config centralizes process-level configuration. It keeps module wiring simple
// and deterministic for API, worker, and CLI binaries.
type Config struct {
	HTTPAddr          string
	LogLevel          string
	Provider          string
	ServiceName       string
	DatabaseURL       string
	AWSFixturePath    []string
	ScanInterval      time.Duration
	WorkerRunNow      bool
	APIKeys           []string
	WriteAPIKeys      []string
	APIKeyScopes      map[string][]string
	RateLimitRPM      int
	RateLimitBurst    int
	RunMigrations     bool
	MigrationsDir     string
	AuditLogFile      string
	AlertWebhookURL   string
	AlertMinSeverity  string
	AlertTimeout      time.Duration
	AlertHMACSecret   string
	AlertMaxFindings  int
	AlertMaxRetries   int
	AlertRetryBackoff time.Duration
}

// Load reads environment variables and applies safe defaults for local and CI use.
func Load() Config {
	return Config{
		HTTPAddr:          getEnv("IDENTRAIL_HTTP_ADDR", defaultHTTPAddr),
		LogLevel:          strings.ToLower(getEnv("IDENTRAIL_LOG_LEVEL", defaultLogLevel)),
		Provider:          strings.ToLower(getEnv("IDENTRAIL_PROVIDER", defaultProvider)),
		ServiceName:       getEnv("IDENTRAIL_SERVICE_NAME", defaultServiceName),
		DatabaseURL:       getEnv("IDENTRAIL_DATABASE_URL", ""),
		AWSFixturePath:    parseCommaSeparated(getEnv("IDENTRAIL_AWS_FIXTURES", defaultAWSFixtures)),
		ScanInterval:      parseDuration(getEnv("IDENTRAIL_SCAN_INTERVAL", defaultScanInterval.String()), defaultScanInterval),
		WorkerRunNow:      parseBool(getEnv("IDENTRAIL_WORKER_RUN_NOW", "true"), true),
		APIKeys:           parseCommaSeparated(getEnv("IDENTRAIL_API_KEYS", "")),
		WriteAPIKeys:      parseCommaSeparated(getEnv("IDENTRAIL_WRITE_API_KEYS", "")),
		APIKeyScopes:      parseKeyScopes(getEnv("IDENTRAIL_API_KEY_SCOPES", "")),
		RateLimitRPM:      parseInt(getEnv("IDENTRAIL_RATE_LIMIT_RPM", "120"), 120),
		RateLimitBurst:    parseInt(getEnv("IDENTRAIL_RATE_LIMIT_BURST", "20"), 20),
		RunMigrations:     parseBool(getEnv("IDENTRAIL_RUN_MIGRATIONS", "true"), true),
		MigrationsDir:     getEnv("IDENTRAIL_MIGRATIONS_DIR", "migrations"),
		AuditLogFile:      getEnv("IDENTRAIL_AUDIT_LOG_FILE", ""),
		AlertWebhookURL:   getEnv("IDENTRAIL_ALERT_WEBHOOK_URL", ""),
		AlertMinSeverity:  strings.ToLower(getEnv("IDENTRAIL_ALERT_MIN_SEVERITY", "high")),
		AlertTimeout:      parseDuration(getEnv("IDENTRAIL_ALERT_TIMEOUT", "5s"), 5*time.Second),
		AlertHMACSecret:   getEnv("IDENTRAIL_ALERT_HMAC_SECRET", ""),
		AlertMaxFindings:  parseInt(getEnv("IDENTRAIL_ALERT_MAX_FINDINGS", "25"), 25),
		AlertMaxRetries:   parseInt(getEnv("IDENTRAIL_ALERT_MAX_RETRIES", "2"), 2),
		AlertRetryBackoff: parseDuration(getEnv("IDENTRAIL_ALERT_RETRY_BACKOFF", "1s"), 1*time.Second),
	}
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseCommaSeparated(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func parseDuration(value string, fallback time.Duration) time.Duration {
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseBool(value string, fallback bool) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func parseInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseKeyScopes(value string) map[string][]string {
	result := map[string][]string{}
	for _, entry := range strings.Split(value, ";") {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		scopes := parseCommaSeparated(parts[1])
		if len(scopes) == 0 {
			continue
		}
		result[key] = scopes
	}
	return result
}
