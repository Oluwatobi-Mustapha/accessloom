package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

const defaultKubectlPath = "kubectl"

// CommandRunner executes external commands. It is injectable for deterministic tests.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// KubectlCollector collects Kubernetes assets through read-only kubectl list calls.
type KubectlCollector struct {
	kubectlPath string
	contextName string
	run         CommandRunner
	now         func() time.Time
}

var _ providers.Collector = (*KubectlCollector)(nil)

// NewKubectlCollector builds a collector that reads data from the active kube context.
func NewKubectlCollector(kubectlPath string, contextName string, runner CommandRunner) *KubectlCollector {
	path := strings.TrimSpace(kubectlPath)
	if path == "" {
		path = defaultKubectlPath
	}
	if runner == nil {
		runner = defaultCommandRunner
	}
	return &KubectlCollector{
		kubectlPath: path,
		contextName: strings.TrimSpace(contextName),
		run:         runner,
		now:         time.Now,
	}
}

type rawList struct {
	Items []json.RawMessage `json:"items"`
}

// Collect fetches service accounts, role bindings, and pods using read-only kubectl calls.
func (c *KubectlCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	collectedAt := c.now().UTC().Format(time.RFC3339Nano)
	assets := make([]providers.RawAsset, 0, 128)
	seen := map[string]struct{}{}

	added, err := c.collectServiceAccounts(ctx, collectedAt, seen)
	if err != nil {
		return nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectRoleBindings(ctx, "rolebindings", true, collectedAt, seen)
	if err != nil {
		return nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectRoleBindings(ctx, "clusterrolebindings", false, collectedAt, seen)
	if err != nil {
		return nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectPods(ctx, collectedAt, seen)
	if err != nil {
		return nil, err
	}
	assets = append(assets, added...)

	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Kind == assets[j].Kind {
			return assets[i].SourceID < assets[j].SourceID
		}
		return assets[i].Kind < assets[j].Kind
	})
	return assets, nil
}

func (c *KubectlCollector) collectServiceAccounts(ctx context.Context, collectedAt string, seen map[string]struct{}) ([]providers.RawAsset, error) {
	items, err := c.list(ctx, "serviceaccounts", true)
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	assets := make([]providers.RawAsset, 0, len(items))
	for i, item := range items {
		var sa ServiceAccount
		if err := json.Unmarshal(item, &sa); err != nil {
			return nil, fmt.Errorf("decode service account item[%d]: %w", i, err)
		}
		sourceID := sourceIDFor("k8s_service_account", sa.Metadata)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      "k8s_service_account",
			SourceID:  sourceID,
			Payload:   item,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func (c *KubectlCollector) collectRoleBindings(ctx context.Context, resource string, allNamespaces bool, collectedAt string, seen map[string]struct{}) ([]providers.RawAsset, error) {
	items, err := c.list(ctx, resource, allNamespaces)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", resource, err)
	}
	assets := make([]providers.RawAsset, 0, len(items))
	for i, item := range items {
		var binding RoleBinding
		if err := json.Unmarshal(item, &binding); err != nil {
			return nil, fmt.Errorf("decode %s item[%d]: %w", resource, i, err)
		}
		sourceID := sourceIDFor("k8s_role_binding", binding.Metadata)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      "k8s_role_binding",
			SourceID:  sourceID,
			Payload:   item,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func (c *KubectlCollector) collectPods(ctx context.Context, collectedAt string, seen map[string]struct{}) ([]providers.RawAsset, error) {
	items, err := c.list(ctx, "pods", true)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	assets := make([]providers.RawAsset, 0, len(items))
	for i, item := range items {
		var pod Pod
		if err := json.Unmarshal(item, &pod); err != nil {
			return nil, fmt.Errorf("decode pod item[%d]: %w", i, err)
		}
		sourceID := sourceIDFor("k8s_pod", pod.Metadata)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      "k8s_pod",
			SourceID:  sourceID,
			Payload:   item,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func (c *KubectlCollector) list(ctx context.Context, resource string, allNamespaces bool) ([]json.RawMessage, error) {
	args := make([]string, 0, 8)
	if c.contextName != "" {
		args = append(args, "--context", c.contextName)
	}
	args = append(args, "get", resource)
	if allNamespaces {
		args = append(args, "--all-namespaces")
	}
	args = append(args, "-o", "json")

	output, err := c.run(ctx, c.kubectlPath, args...)
	if err != nil {
		return nil, fmt.Errorf("run %s %s: %w", c.kubectlPath, strings.Join(args, " "), err)
	}

	var list rawList
	if err := json.Unmarshal(output, &list); err != nil {
		return nil, fmt.Errorf("decode kubectl output: %w", err)
	}
	return list.Items, nil
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}
