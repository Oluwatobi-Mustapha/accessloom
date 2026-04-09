package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

func TestExecuteScanAndFindingsTable(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	stateFile := filepath.Join(t.TempDir(), "state.json")
	fixtureA := repoFixturePath(t, "role_with_policies.json")
	fixtureB := repoFixturePath(t, "role_with_urlencoded_trust.json")

	var scanOut bytes.Buffer
	err := Execute(cfg, []string{
		"--state-file", stateFile,
		"scan",
		"--fixture", fixtureA,
		"--fixture", fixtureB,
		"--output", "table",
	}, &scanOut)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(scanOut.String(), "Scan completed:") {
		t.Fatalf("expected scan summary, got: %q", scanOut.String())
	}
	if !strings.Contains(strings.ToLower(scanOut.String()), "risky trust policy") {
		t.Fatalf("expected risky trust finding in output, got: %q", scanOut.String())
	}

	var findingsOut bytes.Buffer
	err = Execute(cfg, []string{"--state-file", stateFile, "findings"}, &findingsOut)
	if err != nil {
		t.Fatalf("findings failed: %v", err)
	}
	if !strings.Contains(findingsOut.String(), "Last scan:") {
		t.Fatalf("expected findings header, got: %q", findingsOut.String())
	}
}

func TestExecuteScanJSONNoSave(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	fixtureA := repoFixturePath(t, "role_with_policies.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"scan",
		"--fixture", fixtureA,
		"--output", "json",
		"--no-save",
	}, &out)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(out.String(), "\"generated_at\"") {
		t.Fatalf("expected json output, got: %q", out.String())
	}
	if strings.Contains(out.String(), "Saved findings state") {
		t.Fatalf("did not expect save confirmation when --no-save is set")
	}
}

func TestExecuteFindingsMissingState(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	missingState := filepath.Join(t.TempDir(), "missing.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{"--state-file", missingState, "findings"}, &out)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(out.String(), "No findings state found") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestExecuteInvalidOutputFormat(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	fixtureA := repoFixturePath(t, "role_with_policies.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{"scan", "--fixture", fixtureA, "--output", "xml"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteUnsupportedProvider(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "azure"}

	var out bytes.Buffer
	err := Execute(cfg, []string{"scan"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported provider") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteKubernetesScan(t *testing.T) {
	cfg := config.Config{
		ServiceName: "identrail-test",
		Provider:    "kubernetes",
	}
	stateFile := filepath.Join(t.TempDir(), "k8s-state.json")
	sa := repoFixturePathForProvider(t, "kubernetes", "service_account_payments.json")
	rb := repoFixturePathForProvider(t, "kubernetes", "role_binding_cluster_admin.json")
	role := repoFixturePathForProvider(t, "kubernetes", "cluster_role_cluster_admin.json")
	pod := repoFixturePathForProvider(t, "kubernetes", "pod_payments.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"--state-file", stateFile,
		"scan",
		"--fixture", sa,
		"--fixture", role,
		"--fixture", rb,
		"--fixture", pod,
		"--output", "table",
	}, &out)
	if err != nil {
		t.Fatalf("kubernetes scan failed: %v", err)
	}
	lower := strings.ToLower(out.String())
	if !strings.Contains(lower, "broadly privileged") {
		t.Fatalf("expected overprivileged finding in output, got %q", out.String())
	}
}

func TestExecuteRepoScan(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	repo := initCLITestRepoWithSecret(t)

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"repo-scan",
		"--repo", repo,
		"--history-limit", "50",
		"--max-findings", "20",
		"--output", "json",
	}, &out)
	if err != nil {
		t.Fatalf("repo scan failed: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "\"secret_exposure\"") {
		t.Fatalf("expected secret finding output, got %q", body)
	}
	if strings.Contains(body, "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234") {
		t.Fatalf("expected redacted output, got %q", body)
	}
}

func TestExecuteRepoScanValidationErrors(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	var out bytes.Buffer

	if err := Execute(cfg, []string{"repo-scan"}, &out); err == nil {
		t.Fatal("expected --repo validation error")
	}
	if err := Execute(cfg, []string{"repo-scan", "--repo", ".", "--history-limit", "0"}, &out); err == nil {
		t.Fatal("expected history-limit validation error")
	}
	if err := Execute(cfg, []string{"repo-scan", "--repo", ".", "--max-findings", "0"}, &out); err == nil {
		t.Fatal("expected max-findings validation error")
	}
	if err := Execute(cfg, []string{"repo-scan", "--repo", ".", "--output", "xml"}, &out); err == nil {
		t.Fatal("expected output validation error")
	}
}

func TestExecuteAuthzRollbackJSON(t *testing.T) {
	cfg := config.Config{DefaultTenantID: "default", DefaultWorkspaceID: "default"}
	targetVersion := 3
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/v1/authz/policies/rollback" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if got := strings.TrimSpace(r.Header.Get("X-API-Key")); got != "admin-key" {
			t.Fatalf("expected api key header, got %q", got)
		}
		if got := strings.TrimSpace(r.Header.Get("X-Identrail-Tenant-ID")); got != "tenant-a" {
			t.Fatalf("expected tenant header, got %q", got)
		}
		if got := strings.TrimSpace(r.Header.Get("X-Identrail-Workspace-ID")); got != "workspace-a" {
			t.Fatalf("expected workspace header, got %q", got)
		}
		var request authzPolicyRollbackCLIRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if request.TargetVersion != targetVersion {
			t.Fatalf("expected target version %d, got %d", targetVersion, request.TargetVersion)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authzPolicyRollbackCLIResponse{
			PolicySetID:              "central_authorization",
			PreviousEffective:        intPointerForCLITest(2),
			PreviousActiveVersion:    intPointerForCLITest(1),
			PreviousCandidateVersion: intPointerForCLITest(2),
			ActiveVersion:            targetVersion,
			RolloutMode:              "disabled",
			UpdatedAt:                time.Date(2026, 4, 9, 13, 0, 0, 0, time.UTC),
		})
	}))
	defer server.Close()

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"authz", "rollback",
		"--api-url", server.URL,
		"--api-key", "admin-key",
		"--tenant-id", "tenant-a",
		"--workspace-id", "workspace-a",
		"--policy-set-id", "central_authorization",
		"--target-version", "3",
		"--output", "json",
	}, &out)
	if err != nil {
		t.Fatalf("authz rollback failed: %v", err)
	}
	if !strings.Contains(out.String(), "\"active_version\": 3") {
		t.Fatalf("expected rollback json output, got %q", out.String())
	}
}

func TestExecuteAuthzRollbackValidation(t *testing.T) {
	cfg := config.Config{}
	var out bytes.Buffer
	if err := Execute(cfg, []string{"authz", "rollback", "--target-version", "0"}, &out); err == nil {
		t.Fatal("expected target-version validation error")
	}
}

func initCLITestRepoWithSecret(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	runCLITestGit(t, repo, "init", "-q")

	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("AWS_SECRET_ACCESS_KEY=ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	runCLITestGit(t, repo, "add", "app.env")
	runCLITestGit(t, repo, "commit", "-q", "-m", "add secret")
	return repo
}

func runCLITestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=identrail-test",
		"GIT_AUTHOR_EMAIL=identrail-test@example.com",
		"GIT_COMMITTER_NAME=identrail-test",
		"GIT_COMMITTER_EMAIL=identrail-test@example.com",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
}

func TestExecuteKubernetesUnsupportedSource(t *testing.T) {
	cfg := config.Config{
		ServiceName:      "identrail-test",
		Provider:         "kubernetes",
		KubernetesSource: "unknown",
	}
	var out bytes.Buffer
	err := Execute(cfg, []string{"scan", "--no-save"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported kubernetes source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteAWSUnsupportedSource(t *testing.T) {
	cfg := config.Config{
		ServiceName: "identrail-test",
		Provider:    "aws",
		AWSSource:   "unknown",
	}
	var out bytes.Buffer
	err := Execute(cfg, []string{"scan"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported aws source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	var out bytes.Buffer

	err := Execute(cfg, []string{"unknown"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(out.String(), "unknown command") {
		t.Fatalf("expected unknown command output, got: %q", out.String())
	}
}

func TestRenderFindingsTableSeverityOrdering(t *testing.T) {
	findings := []domain.Finding{
		{ID: "f-low", Severity: domain.SeverityLow, Type: domain.FindingOwnerless, Title: "low"},
		{ID: "f-critical", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, Title: "critical"},
		{ID: "f-high", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "high"},
	}

	var out bytes.Buffer
	if err := renderFindingsTable(&out, findings); err != nil {
		t.Fatalf("render table: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %q", out.String())
	}
	if !strings.Contains(lines[0], "[CRITICAL]") || !strings.Contains(lines[0], "critical") {
		t.Fatalf("expected critical finding first, got %q", lines[0])
	}
	if !strings.Contains(lines[2], "[HIGH]") && !strings.Contains(lines[2], "[LOW]") {
		// keep message readable if formatting changes
		t.Fatalf("expected severity-ordered output, got %q", out.String())
	}
}

func TestCLISmokeFlow(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	stateFile := filepath.Join(t.TempDir(), "smoke-state.json")
	fixtureA := repoFixturePath(t, "role_with_policies.json")
	fixtureB := repoFixturePath(t, "role_with_urlencoded_trust.json")

	var scanOut bytes.Buffer
	if err := Execute(cfg, []string{
		"--state-file", stateFile,
		"scan",
		"--fixture", fixtureA,
		"--fixture", fixtureB,
		"--output", "table",
	}, &scanOut); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	var findingsOut bytes.Buffer
	if err := Execute(cfg, []string{
		"--state-file", stateFile,
		"findings",
		"--output", "json",
	}, &findingsOut); err != nil {
		t.Fatalf("findings failed: %v", err)
	}
	if !strings.Contains(findingsOut.String(), "\"findings\"") {
		t.Fatalf("expected findings json output, got %q", findingsOut.String())
	}

	// Best-effort repo scan smoke path with deterministic tiny local repository.
	repo := t.TempDir()
	runCLITestGit(t, repo, "init", "-q")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("smoke"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	runCLITestGit(t, repo, "add", "README.md")
	runCLITestGit(t, repo, "commit", "-q", "-m", "init")

	var repoOut bytes.Buffer
	if err := Execute(cfg, []string{
		"repo-scan",
		"--repo", repo,
		"--history-limit", "10",
		"--max-findings", "20",
		"--output", "table",
	}, &repoOut); err != nil {
		t.Fatalf("repo scan failed: %v", err)
	}
	if !strings.Contains(repoOut.String(), "Repo scan completed:") {
		t.Fatalf("expected repo scan summary, got %q", repoOut.String())
	}
}

func TestSeveritySortRank(t *testing.T) {
	if severitySortRank(domain.SeverityCritical) <= severitySortRank(domain.SeverityHigh) {
		t.Fatal("expected critical rank > high rank")
	}
	if severitySortRank("unknown") != 0 {
		t.Fatalf("expected zero rank for unknown severity, got %d", severitySortRank("unknown"))
	}

	// Keep compile-time guard for ranking usage in sorting comparisons.
	if cmp := compareSeverityForTest(domain.SeverityInfo, domain.SeverityCritical); cmp >= 0 {
		t.Fatalf("expected info to rank below critical, got %d", cmp)
	}
}

func compareSeverityForTest(left domain.FindingSeverity, right domain.FindingSeverity) int {
	return severitySortRank(left) - severitySortRank(right)
}

func intPointerForCLITest(value int) *int {
	result := value
	return &result
}

func repoFixturePath(t *testing.T, name string) string {
	return repoFixturePathForProvider(t, "aws", name)
}

func repoFixturePathForProvider(t *testing.T, provider string, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve caller path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(root, "testdata", provider, name)
}
