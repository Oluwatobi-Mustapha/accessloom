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
	maxRepoScanHistoryLimitMax  = 20000
	maxRepoScanFindingsLimitMax = 5000
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

var allowedKubernetesSources = map[string]struct{}{
	"fixture": {},
	"kubectl": {},
}

var allowedAWSSources = map[string]struct{}{
	"fixture": {},
	"sdk":     {},
}

var allowedLockBackends = map[string]struct{}{
	"auto":     {},
	"inmemory": {},
	"postgres": {},
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
	if strings.ToLower(strings.TrimSpace(cfg.Provider)) == "kubernetes" {
		source := strings.ToLower(strings.TrimSpace(cfg.KubernetesSource))
		if source == "" {
			source = "fixture"
		}
		if _, ok := allowedKubernetesSources[source]; !ok {
			return fmt.Errorf("invalid IDENTRAIL_K8S_SOURCE %q", cfg.KubernetesSource)
		}
		if source == "kubectl" && strings.TrimSpace(cfg.KubectlPath) == "" {
			return fmt.Errorf("IDENTRAIL_KUBECTL_PATH must be set when IDENTRAIL_K8S_SOURCE=kubectl")
		}
	}
	if strings.ToLower(strings.TrimSpace(cfg.Provider)) == "aws" {
		source := strings.ToLower(strings.TrimSpace(cfg.AWSSource))
		if source == "" {
			source = "fixture"
		}
		if _, ok := allowedAWSSources[source]; !ok {
			return fmt.Errorf("invalid IDENTRAIL_AWS_SOURCE %q", cfg.AWSSource)
		}
		if source == "sdk" && strings.TrimSpace(cfg.AWSRegion) == "" {
			return fmt.Errorf("IDENTRAIL_AWS_REGION must be set when IDENTRAIL_AWS_SOURCE=sdk")
		}
	}
	historyLimit := cfg.RepoScanHistoryLimit
	if historyLimit == 0 {
		historyLimit = defaultRepoScanHistoryLimit
	}
	maxFindings := cfg.RepoScanMaxFindings
	if maxFindings == 0 {
		maxFindings = defaultRepoScanMaxFindings
	}
	historyLimitMax := cfg.RepoScanHistoryLimitMax
	if historyLimitMax == 0 {
		historyLimitMax = defaultRepoScanHistoryLimitMax
	}
	maxFindingsMax := cfg.RepoScanMaxFindingsMax
	if maxFindingsMax == 0 {
		maxFindingsMax = defaultRepoScanMaxFindingsLimitMax
	}
	if historyLimit <= 0 {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT must be > 0")
	}
	if maxFindings <= 0 {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_MAX_FINDINGS must be > 0")
	}
	if historyLimitMax <= 0 || historyLimitMax > maxRepoScanHistoryLimitMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX must be > 0 and <= %d", maxRepoScanHistoryLimitMax)
	}
	if maxFindingsMax <= 0 || maxFindingsMax > maxRepoScanFindingsLimitMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX must be > 0 and <= %d", maxRepoScanFindingsLimitMax)
	}
	if historyLimit > historyLimitMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT must be <= IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX")
	}
	if maxFindings > maxFindingsMax {
		return fmt.Errorf("IDENTRAIL_REPO_SCAN_MAX_FINDINGS must be <= IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX")
	}
	if cfg.WorkerRepoScanEnabled {
		if !cfg.RepoScanEnabled {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_ENABLED requires IDENTRAIL_REPO_SCAN_ENABLED=true")
		}
		if cfg.WorkerRepoScanInterval <= 0 {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_INTERVAL must be > 0")
		}
		if len(cfg.WorkerRepoScanTargets) == 0 {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_TARGETS must include at least one repository when worker repo scans are enabled")
		}
		for _, target := range cfg.WorkerRepoScanTargets {
			normalized := strings.TrimSpace(target)
			if normalized == "" {
				continue
			}
			if !configRepoTargetAllowed(normalized, cfg.RepoScanAllowlist) {
				return fmt.Errorf("worker repo scan target %q is outside IDENTRAIL_REPO_SCAN_ALLOWLIST", normalized)
			}
		}
		if cfg.WorkerRepoScanHistory > 0 && cfg.WorkerRepoScanHistory > historyLimitMax {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT must be <= IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX")
		}
		if cfg.WorkerRepoScanFindings > 0 && cfg.WorkerRepoScanFindings > maxFindingsMax {
			return fmt.Errorf("IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS must be <= IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX")
		}
	}
	lockBackend := strings.ToLower(strings.TrimSpace(cfg.LockBackend))
	if lockBackend == "" {
		lockBackend = defaultLockBackend
	}
	if _, ok := allowedLockBackends[lockBackend]; !ok {
		return fmt.Errorf("invalid IDENTRAIL_LOCK_BACKEND %q", cfg.LockBackend)
	}
	if lockBackend == "postgres" && strings.TrimSpace(cfg.DatabaseURL) == "" {
		return fmt.Errorf("IDENTRAIL_LOCK_BACKEND=postgres requires IDENTRAIL_DATABASE_URL")
	}
	if len(cfg.APIKeys) == 0 && len(cfg.APIKeyScopes) == 0 {
		return fmt.Errorf("no API keys configured: set IDENTRAIL_API_KEYS or IDENTRAIL_API_KEY_SCOPES to enable authentication")
	}
	return nil
}

// SecurityWarnings returns non-fatal security posture warnings.
func SecurityWarnings(cfg Config) []string {
	warnings := []string{}
	if len(cfg.APIKeys) > 0 && len(cfg.APIKeyScopes) > 0 {
		warnings = append(warnings, "IDENTRAIL_API_KEYS is ignored when IDENTRAIL_API_KEY_SCOPES is configured")
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
	if cfg.RepoScanEnabled && len(cfg.RepoScanAllowlist) == 0 {
		warnings = append(warnings, "repo scan allowlist is open; set IDENTRAIL_REPO_SCAN_ALLOWLIST to restrict allowed repository targets")
	}
	lockBackend := strings.ToLower(strings.TrimSpace(cfg.LockBackend))
	if lockBackend == "" {
		lockBackend = defaultLockBackend
	}
	if strings.TrimSpace(cfg.DatabaseURL) != "" && lockBackend == "inmemory" {
		warnings = append(warnings, "IDENTRAIL_LOCK_BACKEND is inmemory in database mode; use postgres lock backend for multi-instance deployments")
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

func configRepoTargetAllowed(target string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	normalizedTarget := strings.ToLower(strings.TrimSpace(target))
	if normalizedTarget == "" {
		return false
	}
	for _, pattern := range allowlist {
		normalizedPattern := strings.ToLower(strings.TrimSpace(pattern))
		if normalizedPattern == "" {
			continue
		}
		if strings.HasSuffix(normalizedPattern, "*") {
			prefix := strings.TrimSuffix(normalizedPattern, "*")
			if strings.HasPrefix(normalizedTarget, prefix) {
				return true
			}
			continue
		}
		if normalizedTarget == normalizedPattern {
			return true
		}
	}
	return false
}
