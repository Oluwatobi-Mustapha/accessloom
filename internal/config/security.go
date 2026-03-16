package config

import (
	"fmt"
	"strings"
)

// ValidateSecurity checks hard-fail security misconfigurations.
func ValidateSecurity(cfg Config) error {
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
	return nil
}

// SecurityWarnings returns non-fatal security posture warnings.
func SecurityWarnings(cfg Config) []string {
	warnings := []string{}
	if len(cfg.APIKeys) == 0 && len(cfg.APIKeyScopes) == 0 {
		warnings = append(warnings, "v1 API authentication is disabled (no API keys configured)")
	}
	if strings.TrimSpace(cfg.AuditLogFile) == "" {
		warnings = append(warnings, "audit file sink is disabled; configure IDENTRAIL_AUDIT_LOG_FILE for durable local audit records")
	}
	if strings.TrimSpace(cfg.AlertWebhookURL) != "" && strings.TrimSpace(cfg.AlertHMACSecret) == "" {
		warnings = append(warnings, "alert webhook signing is disabled; set IDENTRAIL_ALERT_HMAC_SECRET to enable request signature verification")
	}
	return warnings
}
