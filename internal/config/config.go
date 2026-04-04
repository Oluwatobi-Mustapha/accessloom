package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPAddr                    = ":8080"
	defaultLogLevel                    = "info"
	defaultProvider                    = "aws"
	defaultServiceName                 = "identrail"
	defaultAWSSource                   = "fixture"
	defaultAWSRegion                   = "us-east-1"
	defaultAWSFixtures                 = "testdata/aws/role_with_policies.json,testdata/aws/role_with_urlencoded_trust.json"
	defaultK8sFixtures                 = "testdata/kubernetes/service_account_payments.json,testdata/kubernetes/cluster_role_cluster_admin.json,testdata/kubernetes/role_binding_cluster_admin.json,testdata/kubernetes/pod_payments.json"
	defaultK8sSource                   = "fixture"
	defaultKubectlPath                 = "kubectl"
	defaultScanInterval                = 15 * time.Minute
	defaultRepoScanEnabled             = false
	defaultRepoScanHistoryLimit        = 500
	defaultRepoScanMaxFindings         = 200
	defaultRepoScanHistoryLimitMax     = 5000
	defaultRepoScanMaxFindingsLimitMax = 1000
	defaultScanQueueMaxPending         = 25
	defaultRepoQueueMaxPending         = 100
	defaultWorkerRepoScanEnabled       = false
	defaultWorkerRepoScanRunNow        = false
	defaultWorkerRepoScanInterval      = 1 * time.Hour
	defaultWorkerAPIJobQueueEnabled    = true
	defaultWorkerAPIJobQueueInterval   = 2 * time.Second
	defaultWorkerAPIJobQueueBatchSize  = 5
	defaultLockBackend                 = "auto"
	defaultLockNamespace               = "identrail"
	defaultTenantID                    = "default"
	defaultWorkspaceID                 = "default"
	defaultOIDCWriteScopes             = "identrail.write,identrail.admin,write,admin"
)

// Config centralizes process-level configuration. It keeps module wiring simple
// and deterministic for API, worker, and CLI binaries.
type Config struct {
	HTTPAddr                   string
	LogLevel                   string
	Provider                   string
	ServiceName                string
	TrustedProxies             []string
	CORSAllowedOrigins         []string
	DatabaseURL                string
	AWSSource                  string
	AWSRegion                  string
	AWSProfile                 string
	AWSFixturePath             []string
	KubernetesFixturePath      []string
	KubernetesSource           string
	KubectlPath                string
	KubeContext                string
	ScanInterval               time.Duration
	WorkerRunNow               bool
	APIKeys                    []string
	WriteAPIKeys               []string
	APIKeyScopes               map[string][]string
	RateLimitRPM               int
	RateLimitBurst             int
	RunMigrations              bool
	MigrationsDir              string
	AuditLogFile               string
	AuditForwardURL            string
	AuditForwardTimeout        time.Duration
	AuditForwardMaxRetries     int
	AuditForwardRetryBackoff   time.Duration
	AuditForwardHMACSecret     string
	AlertWebhookURL            string
	AlertMinSeverity           string
	AlertTimeout               time.Duration
	AlertHMACSecret            string
	AlertMaxFindings           int
	AlertMaxRetries            int
	AlertRetryBackoff          time.Duration
	RepoScanEnabled            bool
	RepoScanHistoryLimit       int
	RepoScanMaxFindings        int
	RepoScanHistoryLimitMax    int
	RepoScanMaxFindingsMax     int
	RepoScanAllowlist          []string
	ScanQueueMaxPending        int
	RepoQueueMaxPending        int
	WorkerRepoScanEnabled      bool
	WorkerRepoScanRunNow       bool
	WorkerRepoScanInterval     time.Duration
	WorkerRepoScanTargets      []string
	WorkerRepoScanHistory      int
	WorkerRepoScanFindings     int
	WorkerAPIJobQueueEnabled   bool
	WorkerAPIJobQueueInterval  time.Duration
	WorkerAPIJobQueueBatchSize int
	LockBackend                string
	LockNamespace              string
	DefaultTenantID            string
	DefaultWorkspaceID         string
	OIDCIssuerURL              string
	OIDCAudience               string
	OIDCWriteScopes            []string
}

// Load reads environment variables and applies safe defaults for local and CI use.
func Load() Config {
	return Config{
		HTTPAddr:                   getEnv("IDENTRAIL_HTTP_ADDR", defaultHTTPAddr),
		LogLevel:                   strings.ToLower(getEnv("IDENTRAIL_LOG_LEVEL", defaultLogLevel)),
		Provider:                   strings.ToLower(getEnv("IDENTRAIL_PROVIDER", defaultProvider)),
		ServiceName:                getEnv("IDENTRAIL_SERVICE_NAME", defaultServiceName),
		TrustedProxies:             parseCommaSeparated(getEnv("IDENTRAIL_TRUSTED_PROXIES", "")),
		CORSAllowedOrigins:         parseCommaSeparated(getEnv("IDENTRAIL_CORS_ALLOWED_ORIGINS", "")),
		DatabaseURL:                getEnv("IDENTRAIL_DATABASE_URL", ""),
		AWSSource:                  strings.ToLower(getEnv("IDENTRAIL_AWS_SOURCE", defaultAWSSource)),
		AWSRegion:                  getEnv("IDENTRAIL_AWS_REGION", defaultAWSRegion),
		AWSProfile:                 getEnv("IDENTRAIL_AWS_PROFILE", ""),
		AWSFixturePath:             parseCommaSeparated(getEnv("IDENTRAIL_AWS_FIXTURES", defaultAWSFixtures)),
		KubernetesFixturePath:      parseCommaSeparated(getEnv("IDENTRAIL_K8S_FIXTURES", defaultK8sFixtures)),
		KubernetesSource:           strings.ToLower(getEnv("IDENTRAIL_K8S_SOURCE", defaultK8sSource)),
		KubectlPath:                getEnv("IDENTRAIL_KUBECTL_PATH", defaultKubectlPath),
		KubeContext:                getEnv("IDENTRAIL_KUBE_CONTEXT", ""),
		ScanInterval:               parseDuration(getEnv("IDENTRAIL_SCAN_INTERVAL", defaultScanInterval.String()), defaultScanInterval),
		WorkerRunNow:               parseBool(getEnv("IDENTRAIL_WORKER_RUN_NOW", "true"), true),
		APIKeys:                    parseCommaSeparated(getEnv("IDENTRAIL_API_KEYS", "")),
		WriteAPIKeys:               parseCommaSeparated(getEnv("IDENTRAIL_WRITE_API_KEYS", "")),
		APIKeyScopes:               parseKeyScopes(getEnv("IDENTRAIL_API_KEY_SCOPES", "")),
		RateLimitRPM:               parseInt(getEnv("IDENTRAIL_RATE_LIMIT_RPM", "120"), 120),
		RateLimitBurst:             parseInt(getEnv("IDENTRAIL_RATE_LIMIT_BURST", "20"), 20),
		RunMigrations:              parseBool(getEnv("IDENTRAIL_RUN_MIGRATIONS", "true"), true),
		MigrationsDir:              getEnv("IDENTRAIL_MIGRATIONS_DIR", "migrations"),
		AuditLogFile:               getEnv("IDENTRAIL_AUDIT_LOG_FILE", ""),
		AuditForwardURL:            getEnv("IDENTRAIL_AUDIT_FORWARD_URL", ""),
		AuditForwardTimeout:        parseDuration(getEnv("IDENTRAIL_AUDIT_FORWARD_TIMEOUT", "3s"), 3*time.Second),
		AuditForwardMaxRetries:     parseInt(getEnv("IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES", "1"), 1),
		AuditForwardRetryBackoff:   parseDuration(getEnv("IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF", "1s"), 1*time.Second),
		AuditForwardHMACSecret:     getEnv("IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET", ""),
		AlertWebhookURL:            getEnv("IDENTRAIL_ALERT_WEBHOOK_URL", ""),
		AlertMinSeverity:           strings.ToLower(getEnv("IDENTRAIL_ALERT_MIN_SEVERITY", "high")),
		AlertTimeout:               parseDuration(getEnv("IDENTRAIL_ALERT_TIMEOUT", "5s"), 5*time.Second),
		AlertHMACSecret:            getEnv("IDENTRAIL_ALERT_HMAC_SECRET", ""),
		AlertMaxFindings:           parseInt(getEnv("IDENTRAIL_ALERT_MAX_FINDINGS", "25"), 25),
		AlertMaxRetries:            parseInt(getEnv("IDENTRAIL_ALERT_MAX_RETRIES", "2"), 2),
		AlertRetryBackoff:          parseDuration(getEnv("IDENTRAIL_ALERT_RETRY_BACKOFF", "1s"), 1*time.Second),
		RepoScanEnabled:            parseBool(getEnv("IDENTRAIL_REPO_SCAN_ENABLED", "false"), defaultRepoScanEnabled),
		RepoScanHistoryLimit:       parseInt(getEnv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT", "500"), defaultRepoScanHistoryLimit),
		RepoScanMaxFindings:        parseInt(getEnv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS", "200"), defaultRepoScanMaxFindings),
		RepoScanHistoryLimitMax:    parseInt(getEnv("IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX", "5000"), defaultRepoScanHistoryLimitMax),
		RepoScanMaxFindingsMax:     parseInt(getEnv("IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX", "1000"), defaultRepoScanMaxFindingsLimitMax),
		RepoScanAllowlist:          parseCommaSeparated(getEnv("IDENTRAIL_REPO_SCAN_ALLOWLIST", "")),
		ScanQueueMaxPending:        parseInt(getEnv("IDENTRAIL_SCAN_QUEUE_MAX_PENDING", "25"), defaultScanQueueMaxPending),
		RepoQueueMaxPending:        parseInt(getEnv("IDENTRAIL_REPO_SCAN_QUEUE_MAX_PENDING", "100"), defaultRepoQueueMaxPending),
		WorkerRepoScanEnabled:      parseBool(getEnv("IDENTRAIL_WORKER_REPO_SCAN_ENABLED", "false"), defaultWorkerRepoScanEnabled),
		WorkerRepoScanRunNow:       parseBool(getEnv("IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW", "false"), defaultWorkerRepoScanRunNow),
		WorkerRepoScanInterval:     parseDuration(getEnv("IDENTRAIL_WORKER_REPO_SCAN_INTERVAL", defaultWorkerRepoScanInterval.String()), defaultWorkerRepoScanInterval),
		WorkerRepoScanTargets:      parseCommaSeparated(getEnv("IDENTRAIL_WORKER_REPO_SCAN_TARGETS", "")),
		WorkerRepoScanHistory:      parseInt(getEnv("IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT", "0"), 0),
		WorkerRepoScanFindings:     parseInt(getEnv("IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS", "0"), 0),
		WorkerAPIJobQueueEnabled:   parseBool(getEnv("IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED", "true"), defaultWorkerAPIJobQueueEnabled),
		WorkerAPIJobQueueInterval:  parseDuration(getEnv("IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL", defaultWorkerAPIJobQueueInterval.String()), defaultWorkerAPIJobQueueInterval),
		WorkerAPIJobQueueBatchSize: parseInt(getEnv("IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE", "5"), defaultWorkerAPIJobQueueBatchSize),
		LockBackend:                strings.ToLower(getEnv("IDENTRAIL_LOCK_BACKEND", defaultLockBackend)),
		LockNamespace:              getEnv("IDENTRAIL_LOCK_NAMESPACE", defaultLockNamespace),
		DefaultTenantID:            getEnv("IDENTRAIL_DEFAULT_TENANT_ID", defaultTenantID),
		DefaultWorkspaceID:         getEnv("IDENTRAIL_DEFAULT_WORKSPACE_ID", defaultWorkspaceID),
		OIDCIssuerURL:              getEnv("IDENTRAIL_OIDC_ISSUER_URL", ""),
		OIDCAudience:               getEnv("IDENTRAIL_OIDC_AUDIENCE", ""),
		OIDCWriteScopes:            parseCommaSeparated(getEnv("IDENTRAIL_OIDC_WRITE_SCOPES", defaultOIDCWriteScopes)),
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
