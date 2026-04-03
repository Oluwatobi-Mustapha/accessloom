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
	t.Setenv("IDENTRAIL_TRUSTED_PROXIES", "")
	t.Setenv("IDENTRAIL_DATABASE_URL", "")
	t.Setenv("IDENTRAIL_AWS_SOURCE", "")
	t.Setenv("IDENTRAIL_AWS_REGION", "")
	t.Setenv("IDENTRAIL_AWS_PROFILE", "")
	t.Setenv("IDENTRAIL_AWS_FIXTURES", "")
	t.Setenv("IDENTRAIL_K8S_FIXTURES", "")
	t.Setenv("IDENTRAIL_K8S_SOURCE", "")
	t.Setenv("IDENTRAIL_KUBECTL_PATH", "")
	t.Setenv("IDENTRAIL_KUBE_CONTEXT", "")
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
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_URL", "")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_TIMEOUT", "")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES", "")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF", "")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET", "")
	t.Setenv("IDENTRAIL_ALERT_WEBHOOK_URL", "")
	t.Setenv("IDENTRAIL_ALERT_MIN_SEVERITY", "")
	t.Setenv("IDENTRAIL_ALERT_TIMEOUT", "")
	t.Setenv("IDENTRAIL_ALERT_HMAC_SECRET", "")
	t.Setenv("IDENTRAIL_ALERT_MAX_FINDINGS", "")
	t.Setenv("IDENTRAIL_ALERT_MAX_RETRIES", "")
	t.Setenv("IDENTRAIL_ALERT_RETRY_BACKOFF", "")
	t.Setenv("IDENTRAIL_REPO_SCAN_ENABLED", "")
	t.Setenv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT", "")
	t.Setenv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS", "")
	t.Setenv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX", "")
	t.Setenv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX", "")
	t.Setenv("IDENTRAIL_REPO_SCAN_ALLOWLIST", "")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_ENABLED", "")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW", "")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_INTERVAL", "")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_TARGETS", "")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT", "")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS", "")
	t.Setenv("IDENTRAIL_LOCK_BACKEND", "")
	t.Setenv("IDENTRAIL_LOCK_NAMESPACE", "")

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
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("expected no trusted proxies by default, got %+v", cfg.TrustedProxies)
	}
	if cfg.DatabaseURL != "" {
		t.Fatalf("expected empty database url, got %q", cfg.DatabaseURL)
	}
	if cfg.AWSSource != defaultAWSSource {
		t.Fatalf("expected default aws source %q, got %q", defaultAWSSource, cfg.AWSSource)
	}
	if cfg.AWSRegion != defaultAWSRegion {
		t.Fatalf("expected default aws region %q, got %q", defaultAWSRegion, cfg.AWSRegion)
	}
	if cfg.AWSProfile != "" {
		t.Fatalf("expected empty aws profile, got %q", cfg.AWSProfile)
	}
	if len(cfg.AWSFixturePath) != 2 {
		t.Fatalf("expected 2 default fixture paths, got %d", len(cfg.AWSFixturePath))
	}
	if len(cfg.KubernetesFixturePath) != 4 {
		t.Fatalf("expected 4 default k8s fixture paths, got %d", len(cfg.KubernetesFixturePath))
	}
	if cfg.KubernetesSource != defaultK8sSource {
		t.Fatalf("expected default k8s source %q, got %q", defaultK8sSource, cfg.KubernetesSource)
	}
	if cfg.KubectlPath != defaultKubectlPath {
		t.Fatalf("expected default kubectl path %q, got %q", defaultKubectlPath, cfg.KubectlPath)
	}
	if cfg.KubeContext != "" {
		t.Fatalf("expected empty kube context by default, got %q", cfg.KubeContext)
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
	if cfg.AuditForwardURL != "" {
		t.Fatalf("expected empty audit forward url, got %q", cfg.AuditForwardURL)
	}
	if cfg.AuditForwardTimeout != 3*time.Second {
		t.Fatalf("expected default audit forward timeout 3s, got %v", cfg.AuditForwardTimeout)
	}
	if cfg.AuditForwardMaxRetries != 1 {
		t.Fatalf("expected default audit forward max retries 1, got %d", cfg.AuditForwardMaxRetries)
	}
	if cfg.AuditForwardRetryBackoff != 1*time.Second {
		t.Fatalf("expected default audit forward retry backoff 1s, got %v", cfg.AuditForwardRetryBackoff)
	}
	if cfg.AuditForwardHMACSecret != "" {
		t.Fatalf("expected empty audit forward hmac secret, got %q", cfg.AuditForwardHMACSecret)
	}
	if cfg.AlertWebhookURL != "" {
		t.Fatalf("expected empty alert webhook url, got %q", cfg.AlertWebhookURL)
	}
	if cfg.AlertMinSeverity != "high" {
		t.Fatalf("expected default alert min severity high, got %q", cfg.AlertMinSeverity)
	}
	if cfg.AlertTimeout != 5*time.Second {
		t.Fatalf("expected default alert timeout 5s, got %v", cfg.AlertTimeout)
	}
	if cfg.AlertHMACSecret != "" {
		t.Fatalf("expected empty alert hmac secret, got %q", cfg.AlertHMACSecret)
	}
	if cfg.AlertMaxFindings != 25 {
		t.Fatalf("expected default alert max findings 25, got %d", cfg.AlertMaxFindings)
	}
	if cfg.AlertMaxRetries != 2 {
		t.Fatalf("expected default alert max retries 2, got %d", cfg.AlertMaxRetries)
	}
	if cfg.AlertRetryBackoff != 1*time.Second {
		t.Fatalf("expected default alert retry backoff 1s, got %v", cfg.AlertRetryBackoff)
	}
	if cfg.RepoScanEnabled {
		t.Fatal("expected repo scan disabled by default")
	}
	if cfg.RepoScanHistoryLimit != 500 {
		t.Fatalf("expected default repo scan history limit 500, got %d", cfg.RepoScanHistoryLimit)
	}
	if cfg.RepoScanMaxFindings != 200 {
		t.Fatalf("expected default repo scan max findings 200, got %d", cfg.RepoScanMaxFindings)
	}
	if cfg.RepoScanHistoryLimitMax != 5000 {
		t.Fatalf("expected default repo scan history limit max 5000, got %d", cfg.RepoScanHistoryLimitMax)
	}
	if cfg.RepoScanMaxFindingsMax != 1000 {
		t.Fatalf("expected default repo scan max findings max 1000, got %d", cfg.RepoScanMaxFindingsMax)
	}
	if len(cfg.RepoScanAllowlist) != 0 {
		t.Fatalf("expected empty repo scan allowlist by default, got %+v", cfg.RepoScanAllowlist)
	}
	if cfg.WorkerRepoScanEnabled {
		t.Fatal("expected worker repo scan disabled by default")
	}
	if cfg.WorkerRepoScanRunNow {
		t.Fatal("expected worker repo scan run now disabled by default")
	}
	if cfg.WorkerRepoScanInterval != defaultWorkerRepoScanInterval {
		t.Fatalf("expected default worker repo scan interval %v, got %v", defaultWorkerRepoScanInterval, cfg.WorkerRepoScanInterval)
	}
	if len(cfg.WorkerRepoScanTargets) != 0 {
		t.Fatalf("expected no worker repo scan targets by default, got %+v", cfg.WorkerRepoScanTargets)
	}
	if cfg.WorkerRepoScanHistory != 0 {
		t.Fatalf("expected default worker repo scan history override 0, got %d", cfg.WorkerRepoScanHistory)
	}
	if cfg.WorkerRepoScanFindings != 0 {
		t.Fatalf("expected default worker repo scan findings override 0, got %d", cfg.WorkerRepoScanFindings)
	}
	if cfg.LockBackend != defaultLockBackend {
		t.Fatalf("expected default lock backend %q, got %q", defaultLockBackend, cfg.LockBackend)
	}
	if cfg.LockNamespace != defaultLockNamespace {
		t.Fatalf("expected default lock namespace %q, got %q", defaultLockNamespace, cfg.LockNamespace)
	}
	if cfg.OIDCIssuerURL != "" {
		t.Fatalf("expected empty oidc issuer by default, got %q", cfg.OIDCIssuerURL)
	}
	if cfg.OIDCAudience != "" {
		t.Fatalf("expected empty oidc audience by default, got %q", cfg.OIDCAudience)
	}
	if len(cfg.OIDCWriteScopes) == 0 {
		t.Fatal("expected default oidc write scopes")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("IDENTRAIL_HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("IDENTRAIL_LOG_LEVEL", "DEBUG")
	t.Setenv("IDENTRAIL_PROVIDER", "AWS")
	t.Setenv("IDENTRAIL_SERVICE_NAME", "identrail-dev")
	t.Setenv("IDENTRAIL_TRUSTED_PROXIES", "10.0.0.0/8,127.0.0.1")
	t.Setenv("IDENTRAIL_DATABASE_URL", "postgres://example")
	t.Setenv("IDENTRAIL_AWS_SOURCE", "sdk")
	t.Setenv("IDENTRAIL_AWS_REGION", "eu-west-1")
	t.Setenv("IDENTRAIL_AWS_PROFILE", "engineering")
	t.Setenv("IDENTRAIL_AWS_FIXTURES", "fixtures/a.json,fixtures/b.json")
	t.Setenv("IDENTRAIL_K8S_FIXTURES", "fixtures/sa.json,fixtures/rb.json")
	t.Setenv("IDENTRAIL_K8S_SOURCE", "kubectl")
	t.Setenv("IDENTRAIL_KUBECTL_PATH", "/usr/local/bin/kubectl")
	t.Setenv("IDENTRAIL_KUBE_CONTEXT", "dev-cluster")
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
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_URL", "https://audit.example.com/events")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_TIMEOUT", "8s")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES", "4")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF", "2s")
	t.Setenv("IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET", "audit-secret")
	t.Setenv("IDENTRAIL_ALERT_WEBHOOK_URL", "https://alerts.example.com/hooks/identrail")
	t.Setenv("IDENTRAIL_ALERT_MIN_SEVERITY", "critical")
	t.Setenv("IDENTRAIL_ALERT_TIMEOUT", "12s")
	t.Setenv("IDENTRAIL_ALERT_HMAC_SECRET", "top-secret")
	t.Setenv("IDENTRAIL_ALERT_MAX_FINDINGS", "40")
	t.Setenv("IDENTRAIL_ALERT_MAX_RETRIES", "4")
	t.Setenv("IDENTRAIL_ALERT_RETRY_BACKOFF", "3s")
	t.Setenv("IDENTRAIL_REPO_SCAN_ENABLED", "false")
	t.Setenv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT", "800")
	t.Setenv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS", "320")
	t.Setenv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX", "9000")
	t.Setenv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX", "1400")
	t.Setenv("IDENTRAIL_REPO_SCAN_ALLOWLIST", "trusted/*,owner/repo")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_ENABLED", "true")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW", "true")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_INTERVAL", "45m")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_TARGETS", "owner/repo,trusted/infra")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT", "700")
	t.Setenv("IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS", "80")
	t.Setenv("IDENTRAIL_LOCK_BACKEND", "postgres")
	t.Setenv("IDENTRAIL_LOCK_NAMESPACE", "prod-identrail")
	t.Setenv("IDENTRAIL_OIDC_ISSUER_URL", "https://iam.example.com/realms/identrail")
	t.Setenv("IDENTRAIL_OIDC_AUDIENCE", "identrail-api")
	t.Setenv("IDENTRAIL_OIDC_WRITE_SCOPES", "identrail.write,identrail.admin")

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
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != "10.0.0.0/8" || cfg.TrustedProxies[1] != "127.0.0.1" {
		t.Fatalf("unexpected trusted proxies: %+v", cfg.TrustedProxies)
	}
	if cfg.DatabaseURL != "postgres://example" {
		t.Fatalf("unexpected database url: %q", cfg.DatabaseURL)
	}
	if cfg.AWSSource != "sdk" {
		t.Fatalf("unexpected aws source: %q", cfg.AWSSource)
	}
	if cfg.AWSRegion != "eu-west-1" {
		t.Fatalf("unexpected aws region: %q", cfg.AWSRegion)
	}
	if cfg.AWSProfile != "engineering" {
		t.Fatalf("unexpected aws profile: %q", cfg.AWSProfile)
	}
	if len(cfg.AWSFixturePath) != 2 || cfg.AWSFixturePath[0] != "fixtures/a.json" || cfg.AWSFixturePath[1] != "fixtures/b.json" {
		t.Fatalf("unexpected fixture paths: %+v", cfg.AWSFixturePath)
	}
	if len(cfg.KubernetesFixturePath) != 2 || cfg.KubernetesFixturePath[0] != "fixtures/sa.json" || cfg.KubernetesFixturePath[1] != "fixtures/rb.json" {
		t.Fatalf("unexpected k8s fixture paths: %+v", cfg.KubernetesFixturePath)
	}
	if cfg.KubernetesSource != "kubectl" {
		t.Fatalf("unexpected k8s source: %q", cfg.KubernetesSource)
	}
	if cfg.KubectlPath != "/usr/local/bin/kubectl" {
		t.Fatalf("unexpected kubectl path: %q", cfg.KubectlPath)
	}
	if cfg.KubeContext != "dev-cluster" {
		t.Fatalf("unexpected kube context: %q", cfg.KubeContext)
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
	if cfg.AuditForwardURL != "https://audit.example.com/events" {
		t.Fatalf("unexpected audit forward url: %q", cfg.AuditForwardURL)
	}
	if cfg.AuditForwardTimeout != 8*time.Second {
		t.Fatalf("unexpected audit forward timeout: %v", cfg.AuditForwardTimeout)
	}
	if cfg.AuditForwardMaxRetries != 4 {
		t.Fatalf("unexpected audit forward max retries: %d", cfg.AuditForwardMaxRetries)
	}
	if cfg.AuditForwardRetryBackoff != 2*time.Second {
		t.Fatalf("unexpected audit forward retry backoff: %v", cfg.AuditForwardRetryBackoff)
	}
	if cfg.AuditForwardHMACSecret != "audit-secret" {
		t.Fatalf("unexpected audit forward hmac secret: %q", cfg.AuditForwardHMACSecret)
	}
	if cfg.AlertWebhookURL != "https://alerts.example.com/hooks/identrail" {
		t.Fatalf("unexpected alert webhook url: %q", cfg.AlertWebhookURL)
	}
	if cfg.AlertMinSeverity != "critical" {
		t.Fatalf("unexpected alert min severity: %q", cfg.AlertMinSeverity)
	}
	if cfg.AlertTimeout != 12*time.Second {
		t.Fatalf("unexpected alert timeout: %v", cfg.AlertTimeout)
	}
	if cfg.AlertHMACSecret != "top-secret" {
		t.Fatalf("unexpected alert hmac secret: %q", cfg.AlertHMACSecret)
	}
	if cfg.AlertMaxFindings != 40 {
		t.Fatalf("unexpected alert max findings: %d", cfg.AlertMaxFindings)
	}
	if cfg.AlertMaxRetries != 4 {
		t.Fatalf("unexpected alert max retries: %d", cfg.AlertMaxRetries)
	}
	if cfg.AlertRetryBackoff != 3*time.Second {
		t.Fatalf("unexpected alert retry backoff: %v", cfg.AlertRetryBackoff)
	}
	if cfg.RepoScanEnabled {
		t.Fatal("expected repo scan enabled false from env")
	}
	if cfg.RepoScanHistoryLimit != 800 {
		t.Fatalf("unexpected repo scan history limit: %d", cfg.RepoScanHistoryLimit)
	}
	if cfg.RepoScanMaxFindings != 320 {
		t.Fatalf("unexpected repo scan max findings: %d", cfg.RepoScanMaxFindings)
	}
	if cfg.RepoScanHistoryLimitMax != 9000 {
		t.Fatalf("unexpected repo scan history max: %d", cfg.RepoScanHistoryLimitMax)
	}
	if cfg.RepoScanMaxFindingsMax != 1400 {
		t.Fatalf("unexpected repo scan max findings max: %d", cfg.RepoScanMaxFindingsMax)
	}
	if len(cfg.RepoScanAllowlist) != 2 || cfg.RepoScanAllowlist[0] != "trusted/*" || cfg.RepoScanAllowlist[1] != "owner/repo" {
		t.Fatalf("unexpected repo scan allowlist: %+v", cfg.RepoScanAllowlist)
	}
	if !cfg.WorkerRepoScanEnabled {
		t.Fatal("expected worker repo scan enabled")
	}
	if !cfg.WorkerRepoScanRunNow {
		t.Fatal("expected worker repo scan run now enabled")
	}
	if cfg.WorkerRepoScanInterval != 45*time.Minute {
		t.Fatalf("unexpected worker repo scan interval: %v", cfg.WorkerRepoScanInterval)
	}
	if len(cfg.WorkerRepoScanTargets) != 2 || cfg.WorkerRepoScanTargets[0] != "owner/repo" || cfg.WorkerRepoScanTargets[1] != "trusted/infra" {
		t.Fatalf("unexpected worker repo scan targets: %+v", cfg.WorkerRepoScanTargets)
	}
	if cfg.WorkerRepoScanHistory != 700 {
		t.Fatalf("unexpected worker repo scan history override: %d", cfg.WorkerRepoScanHistory)
	}
	if cfg.WorkerRepoScanFindings != 80 {
		t.Fatalf("unexpected worker repo scan findings override: %d", cfg.WorkerRepoScanFindings)
	}
	if cfg.LockBackend != "postgres" {
		t.Fatalf("unexpected lock backend: %q", cfg.LockBackend)
	}
	if cfg.LockNamespace != "prod-identrail" {
		t.Fatalf("unexpected lock namespace: %q", cfg.LockNamespace)
	}
	if cfg.OIDCIssuerURL != "https://iam.example.com/realms/identrail" {
		t.Fatalf("unexpected oidc issuer url: %q", cfg.OIDCIssuerURL)
	}
	if cfg.OIDCAudience != "identrail-api" {
		t.Fatalf("unexpected oidc audience: %q", cfg.OIDCAudience)
	}
	if len(cfg.OIDCWriteScopes) != 2 || cfg.OIDCWriteScopes[0] != "identrail.write" || cfg.OIDCWriteScopes[1] != "identrail.admin" {
		t.Fatalf("unexpected oidc write scopes: %+v", cfg.OIDCWriteScopes)
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
