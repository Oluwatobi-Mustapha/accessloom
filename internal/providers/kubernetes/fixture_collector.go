package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

type fixtureHeader struct {
	Kind string     `json:"kind"`
	Meta ObjectMeta `json:"metadata"`
}

// FixtureCollector reads Kubernetes fixture files and emits provider raw assets.
type FixtureCollector struct {
	paths []string
	now   func() time.Time
}

var _ providers.Collector = (*FixtureCollector)(nil)

// NewFixtureCollector builds a fixture collector for deterministic local scans.
func NewFixtureCollector(paths []string) *FixtureCollector {
	return &FixtureCollector{paths: append([]string(nil), paths...), now: time.Now}
}

// Collect loads fixture objects from files/directories.
func (c *FixtureCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	if len(c.paths) == 0 {
		return nil, fmt.Errorf("kubernetes fixture collector requires at least one fixture path")
	}
	expanded, err := expandFixturePaths(c.paths)
	if err != nil {
		return nil, err
	}
	assets := make([]providers.RawAsset, 0, len(expanded))
	seen := map[string]struct{}{}
	collectedAt := c.now().UTC().Format(time.RFC3339Nano)
	for _, path := range expanded {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read fixture %s: %w", path, err)
		}
		var header fixtureHeader
		if err := json.Unmarshal(payload, &header); err != nil {
			return nil, fmt.Errorf("decode fixture %s: %w", path, err)
		}
		kind := normalizeKind(header.Kind)
		if kind == "" {
			continue
		}
		sourceID := sourceIDFor(kind, header.Meta)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      kind,
			SourceID:  sourceID,
			Payload:   payload,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func normalizeKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "serviceaccount":
		return "k8s_service_account"
	case "rolebinding", "clusterrolebinding":
		return "k8s_role_binding"
	case "pod":
		return "k8s_pod"
	default:
		return ""
	}
}

func sourceIDFor(kind string, meta ObjectMeta) string {
	name := strings.TrimSpace(meta.Name)
	ns := strings.TrimSpace(meta.Namespace)
	switch kind {
	case "k8s_service_account":
		if ns == "" || name == "" {
			return ""
		}
		return "k8s:sa:" + ns + ":" + name
	case "k8s_role_binding":
		if name == "" {
			return ""
		}
		if ns == "" {
			return "k8s:rb:cluster:" + name
		}
		return "k8s:rb:" + ns + ":" + name
	case "k8s_pod":
		if ns == "" || name == "" {
			return ""
		}
		return "k8s:pod:" + ns + ":" + name
	default:
		return ""
	}
}

func expandFixturePaths(inputs []string) ([]string, error) {
	expanded := make([]string, 0, len(inputs))
	for _, input := range inputs {
		cleaned := strings.TrimSpace(input)
		if cleaned == "" {
			continue
		}
		info, err := os.Stat(cleaned)
		if err != nil {
			return nil, fmt.Errorf("stat fixture path %s: %w", cleaned, err)
		}
		if !info.IsDir() {
			expanded = append(expanded, cleaned)
			continue
		}
		entries, err := os.ReadDir(cleaned)
		if err != nil {
			return nil, fmt.Errorf("read fixture directory %s: %w", cleaned, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
				expanded = append(expanded, filepath.Join(cleaned, entry.Name()))
			}
		}
	}
	sort.Strings(expanded)
	if len(expanded) == 0 {
		return nil, fmt.Errorf("no fixture files found")
	}
	return expanded, nil
}
