package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeCommandExec struct {
	responses map[string][]byte
	errs      map[string]error
	commands  []string
}

func (f *fakeCommandExec) run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.commands = append(f.commands, cmd)
	if err, ok := f.errs[cmd]; ok {
		return nil, err
	}
	if out, ok := f.responses[cmd]; ok {
		return out, nil
	}
	return nil, errors.New("unexpected command: " + cmd)
}

func TestKubectlCollectorCollect(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl --context dev get serviceaccounts --all-namespaces -o json": []byte(`{"items":[
				{"kind":"ServiceAccount","metadata":{"name":"payments-api","namespace":"apps","labels":{"team":"payments"}}},
				{"kind":"ServiceAccount","metadata":{"name":"payments-api","namespace":"apps","labels":{"team":"payments"}}}
			]}`),
			"kubectl --context dev get rolebindings --all-namespaces -o json": []byte(`{"items":[
				{"kind":"RoleBinding","metadata":{"name":"payments-read","namespace":"apps"},"roleRef":{"kind":"Role","name":"view"},"subjects":[{"kind":"ServiceAccount","name":"payments-api","namespace":"apps"}]}
			]}`),
			"kubectl --context dev get clusterrolebindings -o json": []byte(`{"items":[
				{"kind":"ClusterRoleBinding","metadata":{"name":"payments-admin"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"payments-api","namespace":"apps"}]}
			]}`),
			"kubectl --context dev get pods --all-namespaces -o json": []byte(`{"items":[
				{"kind":"Pod","metadata":{"name":"payments-api-0","namespace":"apps"},"spec":{"serviceAccountName":"payments-api"}}
			]}`),
		},
	}

	collector := NewKubectlCollector("kubectl", "dev", exec.run)
	collector.now = func() time.Time { return time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC) }

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 4 {
		t.Fatalf("expected 4 deduplicated assets, got %d", len(assets))
	}
	for _, asset := range assets {
		if asset.Collected != "2026-03-17T12:00:00Z" {
			t.Fatalf("unexpected collected timestamp: %q", asset.Collected)
		}
	}
	if got := len(exec.commands); got != 4 {
		t.Fatalf("expected 4 kubectl calls, got %d", got)
	}
}

func TestKubectlCollectorUsesDefaults(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl get serviceaccounts --all-namespaces -o json": []byte(`{"items":[]}`),
			"kubectl get rolebindings --all-namespaces -o json":    []byte(`{"items":[]}`),
			"kubectl get clusterrolebindings -o json":              []byte(`{"items":[]}`),
			"kubectl get pods --all-namespaces -o json":            []byte(`{"items":[]}`),
		},
	}
	collector := NewKubectlCollector("", "", exec.run)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("collect failed: %v", err)
	}
}

func TestKubectlCollectorCommandError(t *testing.T) {
	exec := &fakeCommandExec{
		errs: map[string]error{
			"kubectl get serviceaccounts --all-namespaces -o json": errors.New("forbidden"),
		},
	}
	collector := NewKubectlCollector("kubectl", "", exec.run)
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "list serviceaccounts") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubectlCollectorInvalidJSON(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl get serviceaccounts --all-namespaces -o json": []byte(`not-json`),
		},
	}
	collector := NewKubectlCollector("kubectl", "", exec.run)
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decode kubectl output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubectlCollectorMalformedItem(t *testing.T) {
	exec := &fakeCommandExec{
		responses: map[string][]byte{
			"kubectl get serviceaccounts --all-namespaces -o json": []byte(`{"items":[{"metadata":{"name":"sa","namespace":"apps"}}]}`),
			"kubectl get rolebindings --all-namespaces -o json":    []byte(`{"items":[{"kind":"RoleBinding","metadata":{"name":"rb","namespace":"apps"}}]}`),
			"kubectl get clusterrolebindings -o json":              []byte(`{"items":[{"kind":"ClusterRoleBinding","metadata":{"name":"crb"}}]}`),
			"kubectl get pods --all-namespaces -o json":            []byte(`{"items":[invalid]}`),
		},
	}
	collector := NewKubectlCollector("kubectl", "", exec.run)
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
