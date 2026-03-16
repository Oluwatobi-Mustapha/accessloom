package config

import (
	"os"
	"strings"
)

const (
	defaultHTTPAddr    = ":8080"
	defaultLogLevel    = "info"
	defaultProvider    = "aws"
	defaultServiceName = "identrail"
	defaultAWSFixtures = "testdata/aws/role_with_policies.json,testdata/aws/role_with_urlencoded_trust.json"
)

// Config centralizes process-level configuration. It keeps module wiring simple
// and deterministic for API, worker, and CLI binaries.
type Config struct {
	HTTPAddr       string
	LogLevel       string
	Provider       string
	ServiceName    string
	DatabaseURL    string
	AWSFixturePath []string
}

// Load reads environment variables and applies safe defaults for local and CI use.
func Load() Config {
	return Config{
		HTTPAddr:       getEnv("IDENTRAIL_HTTP_ADDR", defaultHTTPAddr),
		LogLevel:       strings.ToLower(getEnv("IDENTRAIL_LOG_LEVEL", defaultLogLevel)),
		Provider:       strings.ToLower(getEnv("IDENTRAIL_PROVIDER", defaultProvider)),
		ServiceName:    getEnv("IDENTRAIL_SERVICE_NAME", defaultServiceName),
		DatabaseURL:    getEnv("IDENTRAIL_DATABASE_URL", ""),
		AWSFixturePath: parseCommaSeparated(getEnv("IDENTRAIL_AWS_FIXTURES", defaultAWSFixtures)),
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
