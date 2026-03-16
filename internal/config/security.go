package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	maxAlertFindingsLimit       = 500
	maxAlertRetriesLimit        = 10
	maxAlertBackoffLimit        = 30
	maxAuditForwardRetriesLimit = 10
	maxAuditForwardBackoffLimit = 30
)

var allowedKeyScopes = map[string]struct{}{
	"read":  {},
	"write": {},
	"admin": {},
}

var allowedAlertSeverities = map[string]struct{}{
	"info":     {},
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

// ValidateSecurity checks hard-fail security misconfigurations.
func ValidateSecurity(cfg Config) error {
	if len(cfg.APIKeyScopes) > 0 {
		for key, scopes := range cfg.APIKeyScopes {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				return fmt.Errorf("scoped api key cannot be empty")
			}
			validScopeCount := 0
			for _, scope := range scopes {
				normalizedScope := strings.ToLower(strings.TrimSpace(scope))
				if normalizedScope == "" {
					continue
				}
				if _, ok := allowedKeyScopes[normalizedScope]; !ok {
					return fmt.Errorf("invalid scope %q for api key %q", normalizedScope, trimmedKey)
				}
				validScopeCount++
			}
			if validScopeCount == 0 {
				return fmt.Errorf("api key %q has no valid scopes", trimmedKey)
			}
		}
	}

	if len(cfg.APIKeyScopes) == 0 && len(cfg.WriteAPIKeys) > 0 {
		allowed := map[string]struct{}{}
		for _, key := range cfg.APIKeys {
			trimmed := strings.TrimSpace(key)
			if trimmed == "" {
				continue
			}
			allowed[trimmed] = struct{}{}
		}
		for _, writeKey := range cfg.WriteAPIKeys {
			trimmed := strings.TrimSpace(writeKey)
			if trimmed == "" {
				continue
			}
			if _, ok := allowed[trimmed]; !ok {
				return fmt.Errorf("write api key %q must also exist in IDENTRAIL_API_KEYS", trimmed)
			}
		}
	}

	if cfg.AlertMaxFindings > maxAlertFindingsLimit {
		return fmt.Errorf("IDENTRAIL_ALERT_MAX_FINDINGS must be <= %d", maxAlertFindingsLimit)
	}
	if cfg.AlertMaxRetries > maxAlertRetriesLimit {
		return fmt.Errorf("IDENTRAIL_ALERT_MAX_RETRIES must be <= %d", maxAlertRetriesLimit)
	}
	if cfg.AlertRetryBackoff > time.Duration(maxAlertBackoffLimit)*time.Second {
		return fmt.Errorf("IDENTRAIL_ALERT_RETRY_BACKOFF must be <= %ds", maxAlertBackoffLimit)
	}
	if cfg.AuditForwardTimeout > 30*time.Second {
		return fmt.Errorf("IDENTRAIL_AUDIT_FORWARD_TIMEOUT must be <= 30s")
	}
	if cfg.AuditForwardMaxRetries > maxAuditForwardRetriesLimit {
		return fmt.Errorf("IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES must be <= %d", maxAuditForwardRetriesLimit)
	}
	if cfg.AuditForwardRetryBackoff > time.Duration(maxAuditForwardBackoffLimit)*time.Second {
		return fmt.Errorf("IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF must be <= %ds", maxAuditForwardBackoffLimit)
	}
	if strings.TrimSpace(cfg.AuditForwardURL) != "" {
		if err := validateForwardURL(cfg.AuditForwardURL); err != nil {
			return err
		}
	}

	if strings.TrimSpace(cfg.AlertWebhookURL) != "" {
		severity := strings.ToLower(strings.TrimSpace(cfg.AlertMinSeverity))
		if _, ok := allowedAlertSeverities[severity]; !ok {
			return fmt.Errorf("invalid IDENTRAIL_ALERT_MIN_SEVERITY %q", cfg.AlertMinSeverity)
		}
	}
	return nil
}

// SecurityWarnings returns non-fatal security posture warnings.
func SecurityWarnings(cfg Config) []string {
	warnings := []string{}
	if len(cfg.APIKeys) > 0 && len(cfg.APIKeyScopes) > 0 {
		warnings = append(warnings, "IDENTRAIL_API_KEYS is ignored when IDENTRAIL_API_KEY_SCOPES is configured")
	}
	if len(cfg.APIKeys) == 0 && len(cfg.APIKeyScopes) == 0 {
		warnings = append(warnings, "v1 API authentication is disabled (no API keys configured)")
	}
	if strings.TrimSpace(cfg.AuditLogFile) == "" {
		warnings = append(warnings, "audit file sink is disabled; configure IDENTRAIL_AUDIT_LOG_FILE for durable local audit records")
	}
	if strings.TrimSpace(cfg.AuditForwardURL) != "" && strings.TrimSpace(cfg.AuditForwardHMACSecret) == "" {
		warnings = append(warnings, "audit forward signing is disabled; set IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET to enable receiver signature verification")
	}
	if strings.TrimSpace(cfg.AlertWebhookURL) != "" && strings.TrimSpace(cfg.AlertHMACSecret) == "" {
		warnings = append(warnings, "alert webhook signing is disabled; set IDENTRAIL_ALERT_HMAC_SECRET to enable request signature verification")
	}
	return warnings
}

func validateForwardURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse audit forward url: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("insecure audit forward url scheme http is only allowed for localhost")
	default:
		return fmt.Errorf("unsupported audit forward url scheme %q", parsed.Scheme)
	}
}
