package config

import (
	"testing"
	"time"
)

func TestValidateSecurityRejectsNoAPIKeys(t *testing.T) {
	cfg := Config{} // no APIKeys or APIKeyScopes
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected error when no API keys configured")
	}
}

func TestValidateSecurityWriteKeyMustBeInAPIKeys(t *testing.T) {
	cfg := Config{
		APIKeys:      []string{"reader"},
		WriteAPIKeys: []string{"writer"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateSecurityWriteKeyCheckSkippedWhenScopedKeysPresent(t *testing.T) {
	cfg := Config{
		WriteAPIKeys: []string{"writer"},
		APIKeyScopes: map[string][]string{"writer": {"write"}},
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected validation success, got %v", err)
	}
}

func TestValidateSecuritySuccess(t *testing.T) {
	cfg := Config{
		APIKeys:      []string{"reader", "writer"},
		WriteAPIKeys: []string{"writer"},
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected validation success, got %v", err)
	}
}

func TestValidateSecurityRejectsInvalidAWSSource(t *testing.T) {
	cfg := Config{
		Provider:  "aws",
		AWSSource: "invalid",
		APIKeys:   []string{"reader"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected invalid aws source error")
	}
}

func TestValidateSecurityRejectsEmptyAWSRegionInSDKMode(t *testing.T) {
	cfg := Config{
		Provider:  "aws",
		AWSSource: "sdk",
		AWSRegion: "",
		APIKeys:   []string{"reader"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected aws region validation error")
	}
}

func TestValidateSecurityAcceptsAWSSDKMode(t *testing.T) {
	cfg := Config{
		Provider:  "aws",
		AWSSource: "sdk",
		AWSRegion: "us-east-1",
		APIKeys:   []string{"reader"},
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected aws sdk mode to be valid, got %v", err)
	}
}

func TestValidateSecurityRejectsInvalidKubernetesSource(t *testing.T) {
	cfg := Config{
		Provider:         "kubernetes",
		KubernetesSource: "invalid",
		APIKeys:          []string{"reader"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected invalid kubernetes source error")
	}
}

func TestValidateSecurityRejectsEmptyKubectlPath(t *testing.T) {
	cfg := Config{
		Provider:         "kubernetes",
		KubernetesSource: "kubectl",
		KubectlPath:      "",
		APIKeys:          []string{"reader"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected missing kubectl path error")
	}
}

func TestValidateSecurityAcceptsKubectlMode(t *testing.T) {
	cfg := Config{
		Provider:         "kubernetes",
		KubernetesSource: "kubectl",
		KubectlPath:      "/usr/bin/kubectl",
		APIKeys:          []string{"reader"},
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected kubectl mode to be valid, got %v", err)
	}
}

func TestValidateSecurityRejectsInvalidScopedKeyScope(t *testing.T) {
	cfg := Config{
		APIKeyScopes: map[string][]string{"key1": {"invalid"}},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected invalid scope error")
	}
}

func TestValidateSecurityRejectsScopedKeyWithoutValidScope(t *testing.T) {
	cfg := Config{
		APIKeyScopes: map[string][]string{"key1": {""}},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected empty scope error")
	}
}

func TestValidateSecurityRejectsLargeAlertMaxFindings(t *testing.T) {
	cfg := Config{
		AlertMaxFindings: maxAlertFindingsLimit + 1,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected alert max findings validation error")
	}
}

func TestValidateSecurityRejectsInvalidAlertSeverity(t *testing.T) {
	cfg := Config{
		AlertWebhookURL:  "https://alerts.example.com/hook",
		AlertMinSeverity: "extreme",
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected alert severity validation error")
	}
}

func TestValidateSecurityRejectsLargeAlertRetries(t *testing.T) {
	cfg := Config{
		AlertMaxRetries: maxAlertRetriesLimit + 1,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected alert retries validation error")
	}
}

func TestValidateSecurityRejectsLargeAlertBackoff(t *testing.T) {
	cfg := Config{
		AlertRetryBackoff: time.Duration(maxAlertBackoffLimit+1) * time.Second,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected alert backoff validation error")
	}
}

func TestValidateSecurityRejectsInsecureAuditForwardURL(t *testing.T) {
	cfg := Config{
		AuditForwardURL: "http://example.com/events",
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected audit forward url validation error")
	}
}

func TestValidateSecurityRejectsLargeAuditForwardTimeout(t *testing.T) {
	cfg := Config{
		AuditForwardURL:     "https://audit.example.com/events",
		AuditForwardTimeout: 31 * time.Second,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected audit forward timeout validation error")
	}
}

func TestValidateSecurityRejectsLargeAuditForwardRetries(t *testing.T) {
	cfg := Config{
		AuditForwardMaxRetries: maxAuditForwardRetriesLimit + 1,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected audit forward retries validation error")
	}
}

func TestValidateSecurityRejectsLargeAuditForwardBackoff(t *testing.T) {
	cfg := Config{
		AuditForwardRetryBackoff: time.Duration(maxAuditForwardBackoffLimit+1) * time.Second,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected audit forward retry backoff validation error")
	}
}

func TestValidateSecurityRejectsInvalidRepoScanBounds(t *testing.T) {
	cfg := Config{
		APIKeys:                 []string{"reader"},
		RepoScanHistoryLimit:    1000,
		RepoScanHistoryLimitMax: 100,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected repo scan history bound validation error")
	}
}

func TestValidateSecurityWorkerRepoScanRequiresTargets(t *testing.T) {
	cfg := Config{
		APIKeys:                []string{"reader"},
		RepoScanEnabled:        true,
		WorkerRepoScanEnabled:  true,
		WorkerRepoScanInterval: 30 * time.Minute,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected worker repo target validation error")
	}
}

func TestValidateSecurityWorkerRepoScanRequiresRepoScanEnabled(t *testing.T) {
	cfg := Config{
		APIKeys:                []string{"reader"},
		RepoScanEnabled:        false,
		WorkerRepoScanEnabled:  true,
		WorkerRepoScanInterval: 30 * time.Minute,
		WorkerRepoScanTargets:  []string{"owner/repo"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected repo scan enabled dependency error")
	}
}

func TestValidateSecurityWorkerRepoScanAllowlistEnforced(t *testing.T) {
	cfg := Config{
		APIKeys:                []string{"reader"},
		RepoScanEnabled:        true,
		RepoScanAllowlist:      []string{"trusted/*"},
		WorkerRepoScanEnabled:  true,
		WorkerRepoScanInterval: 30 * time.Minute,
		WorkerRepoScanTargets:  []string{"owner/repo"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected allowlist violation")
	}
}

func TestValidateSecurityWorkerRepoScanSuccess(t *testing.T) {
	cfg := Config{
		APIKeys:                 []string{"reader"},
		RepoScanEnabled:         true,
		RepoScanAllowlist:       []string{"trusted/*"},
		RepoScanHistoryLimitMax: 5000,
		RepoScanMaxFindingsMax:  1000,
		WorkerRepoScanEnabled:   true,
		WorkerRepoScanInterval:  30 * time.Minute,
		WorkerRepoScanTargets:   []string{"trusted/repo"},
		WorkerRepoScanHistory:   300,
		WorkerRepoScanFindings:  100,
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected worker repo scan config valid, got %v", err)
	}
}

func TestValidateSecurityRejectsInvalidLockBackend(t *testing.T) {
	cfg := Config{
		APIKeys:     []string{"reader"},
		LockBackend: "redis",
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected invalid lock backend error")
	}
}

func TestValidateSecurityRejectsPostgresLockWithoutDatabase(t *testing.T) {
	cfg := Config{
		APIKeys:     []string{"reader"},
		LockBackend: "postgres",
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected postgres lock database dependency error")
	}
}

func TestSecurityWarningsInMemoryLockInDatabaseMode(t *testing.T) {
	cfg := Config{
		APIKeys:         []string{"reader"},
		DatabaseURL:     "postgres://example",
		LockBackend:     "inmemory",
		RepoScanEnabled: false,
	}
	warnings := SecurityWarnings(cfg)
	found := false
	for _, warning := range warnings {
		if warning == "IDENTRAIL_LOCK_BACKEND is inmemory in database mode; use postgres lock backend for multi-instance deployments" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected lock backend warning, got %+v", warnings)
	}
}

func TestSecurityWarningsRepoScanAllowlist(t *testing.T) {
	cfg := Config{
		APIKeys:         []string{"reader"},
		RepoScanEnabled: true,
	}
	warnings := SecurityWarnings(cfg)
	found := false
	for _, warning := range warnings {
		if warning == "repo scan allowlist is open; set IDENTRAIL_REPO_SCAN_ALLOWLIST to restrict allowed repository targets" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected repo scan allowlist warning, got %+v", warnings)
	}
}

func TestSecurityWarnings(t *testing.T) {
	cfg := Config{
		APIKeys:         []string{"legacy-key"},
		APIKeyScopes:    map[string][]string{"reader-key": {"read"}},
		AlertWebhookURL: "https://alerts.example.com/hook",
	}
	warnings := SecurityWarnings(cfg)
	if len(warnings) < 3 {
		t.Fatalf("expected multiple warnings, got %+v", warnings)
	}
}
