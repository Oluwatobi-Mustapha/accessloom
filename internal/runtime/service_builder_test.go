package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	goruntime "runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
)

func TestBuildScanServiceMemoryStore(t *testing.T) {
	cfg := config.Config{
		Provider:       "aws",
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
		ScanInterval:   5 * time.Minute,
	}

	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc == nil || closeFn == nil {
		t.Fatal("expected non-nil service and close function")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestBuildScanServiceRepoScanSettings(t *testing.T) {
	cfg := config.Config{
		Provider:                "aws",
		AWSFixturePath:          []string{"testdata/aws/role_with_policies.json"},
		RepoScanEnabled:         true,
		RepoScanHistoryLimit:    700,
		RepoScanMaxFindings:     120,
		RepoScanHistoryLimitMax: 2500,
		RepoScanMaxFindingsMax:  900,
		RepoScanAllowlist:       []string{"trusted/*"},
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if !svc.RepoScanEnabled || svc.RepoScanDefaultHistoryLimit != 700 || svc.RepoScanDefaultMaxFindings != 120 {
		t.Fatalf("unexpected repo scan defaults on service: enabled=%t history=%d findings=%d", svc.RepoScanEnabled, svc.RepoScanDefaultHistoryLimit, svc.RepoScanDefaultMaxFindings)
	}
	if svc.RepoScanMaxHistoryLimit != 2500 || svc.RepoScanMaxFindingsLimit != 900 {
		t.Fatalf("unexpected repo scan max bounds on service: history=%d findings=%d", svc.RepoScanMaxHistoryLimit, svc.RepoScanMaxFindingsLimit)
	}
	if len(svc.RepoScanAllowedTargets) != 1 || svc.RepoScanAllowedTargets[0] != "trusted/*" {
		t.Fatalf("unexpected repo scan allowlist %+v", svc.RepoScanAllowedTargets)
	}
}

func TestBuildScanServiceLockDefaults(t *testing.T) {
	cfg := config.Config{
		Provider:       "aws",
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
		LockBackend:    "inmemory",
		LockNamespace:  "tenant-a",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if svc.LockNamespace != "tenant-a" {
		t.Fatalf("unexpected lock namespace %q", svc.LockNamespace)
	}
	if _, ok := svc.Locker.(*scheduler.InMemoryLocker); !ok {
		t.Fatalf("expected in-memory locker, got %T", svc.Locker)
	}
}

func TestBuildScanServiceLockBackendAutoWithoutDatabase(t *testing.T) {
	cfg := config.Config{
		Provider:       "aws",
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
		LockBackend:    "auto",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if _, ok := svc.Locker.(*scheduler.InMemoryLocker); !ok {
		t.Fatalf("expected in-memory locker for auto mode without database, got %T", svc.Locker)
	}
}

func TestBuildScanServiceKubernetesProvider(t *testing.T) {
	cfg := config.Config{
		Provider: "kubernetes",
		KubernetesFixturePath: []string{
			repoFixturePathForProvider(t, "kubernetes", "service_account_payments.json"),
			repoFixturePathForProvider(t, "kubernetes", "role_binding_cluster_admin.json"),
			repoFixturePathForProvider(t, "kubernetes", "pod_payments.json"),
		},
		ScanInterval: 5 * time.Minute,
	}

	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc == nil || closeFn == nil {
		t.Fatal("expected non-nil service and close function")
	}
	if _, err := svc.RunScan(context.Background()); err != nil {
		t.Fatalf("kubernetes scan failed: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestBuildScanServiceUnsupportedProvider(t *testing.T) {
	cfg := config.Config{
		Provider: "azure",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected unsupported provider error")
	}
}

func TestBuildScanServiceUnsupportedAWSSource(t *testing.T) {
	cfg := config.Config{
		Provider:  "aws",
		AWSSource: "unknown",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected unsupported aws source error")
	}
}

func TestBuildScanServiceAWSSDKMode(t *testing.T) {
	cfg := config.Config{
		Provider:  "aws",
		AWSSource: "sdk",
		AWSRegion: "us-east-1",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc == nil || closeFn == nil {
		t.Fatal("expected non-nil service and close function")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestBuildScanServiceUnsupportedKubernetesSource(t *testing.T) {
	cfg := config.Config{
		Provider:         "kubernetes",
		KubernetesSource: "unknown",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected unsupported kubernetes source error")
	}
}

func TestBuildScanServiceKubernetesKubectlMode(t *testing.T) {
	cfg := config.Config{
		Provider:         "kubernetes",
		KubernetesSource: "kubectl",
		KubectlPath:      "/path/does/not/exist/kubectl",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()
	if _, runErr := svc.RunScan(context.Background()); runErr == nil {
		t.Fatal("expected kubectl runtime error")
	}
}

func TestNewStoreMemoryAndInvalidPostgres(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("expected memory store, got err: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close memory store: %v", err)
	}

	_, err = NewStore("postgres://user:pass@127.0.0.1:1/identrail?sslmode=disable&connect_timeout=1")
	if err == nil {
		t.Fatal("expected postgres init error")
	}
}

func TestBuildScanServiceInvalidAlertWebhookConfig(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		AlertWebhookURL:  "http://example.com/hook",
		AlertMinSeverity: "high",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected alert webhook validation error")
	}
}

func TestBuildScanServiceWithAlertWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.Config{
		Provider:         "aws",
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		AlertWebhookURL:  server.URL,
		AlertMinSeverity: "high",
		AlertTimeout:     2 * time.Second,
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc.Alerter == nil {
		t.Fatal("expected alerter to be configured")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestBuildScanServiceAlertWebhookRetriesOnTransientFailure(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&requests, 1)
		if current < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("retry"))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.Config{
		Provider:          "aws",
		AWSFixturePath:    []string{repoFixturePath(t, "role_with_policies.json")},
		AlertWebhookURL:   server.URL,
		AlertMinSeverity:  "high",
		AlertTimeout:      2 * time.Second,
		AlertMaxRetries:   3,
		AlertRetryBackoff: 1 * time.Millisecond,
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if _, err := svc.RunScan(context.Background()); err != nil {
		t.Fatalf("run scan failed: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got < 3 {
		t.Fatalf("expected at least 3 webhook attempts, got %d", got)
	}
}

func repoFixturePath(t *testing.T, name string) string {
	return repoFixturePathForProvider(t, "aws", name)
}

func repoFixturePathForProvider(t *testing.T, provider string, name string) string {
	t.Helper()
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("could not resolve caller path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(root, "testdata", provider, name)
}
