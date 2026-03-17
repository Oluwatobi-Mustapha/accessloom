package cli

import (
	"bytes"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
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
	pod := repoFixturePathForProvider(t, "kubernetes", "pod_payments.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"--state-file", stateFile,
		"scan",
		"--fixture", sa,
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
