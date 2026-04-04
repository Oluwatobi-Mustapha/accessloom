package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

const (
	modeOff             = "off"
	modeNewFindingsOnly = "new-findings-only"
)

type Config struct {
	Version         string   `json:"version"`
	Mode            string   `json:"mode"`
	KnownFindingIDs []string `json:"known_finding_ids"`
}

func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{Mode: modeOff}, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read baseline: %w", err)
	}

	cfg := Config{Mode: modeNewFindingsOnly}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse baseline JSON: %w", err)
	}
	if err := validateConfig(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Apply(cfg Config, result model.ReviewResult) model.ReviewResult {
	normalizedMode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if normalizedMode == "" {
		normalizedMode = modeNewFindingsOnly
	}

	if result.Metadata == nil {
		result.Metadata = map[string]string{}
	}
	result.Metadata["baseline_mode"] = normalizedMode
	if strings.TrimSpace(cfg.Version) != "" {
		result.Metadata["baseline_version"] = strings.TrimSpace(cfg.Version)
	}

	if normalizedMode != modeNewFindingsOnly {
		return result
	}

	known := make(map[string]struct{}, len(cfg.KnownFindingIDs))
	for _, id := range cfg.KnownFindingIDs {
		value := strings.TrimSpace(id)
		if value == "" {
			continue
		}
		known[value] = struct{}{}
	}

	if len(known) == 0 {
		result.Metadata["baseline_suppressed_findings"] = "0"
		return result
	}

	filtered := make([]model.Finding, 0, len(result.Findings))
	suppressed := 0
	for _, finding := range result.Findings {
		if _, ok := known[strings.TrimSpace(finding.ID)]; ok {
			suppressed++
			continue
		}
		filtered = append(filtered, finding)
	}

	result.Findings = filtered
	result.Metadata["baseline_suppressed_findings"] = fmt.Sprintf("%d", suppressed)

	if suppressed == 0 {
		return result
	}

	switch {
	case len(filtered) > 0:
		result.Status = "findings"
		result.Summary = fmt.Sprintf("Detected %d new deterministic finding(s) after baseline filtering.", len(filtered))
	case len(result.Abstain) > 0:
		result.Status = "abstain"
		result.Summary = "No new deterministic findings after baseline filtering; reviewer abstained on at least one check."
	default:
		result.Status = "clean"
		result.Summary = "No new deterministic findings after baseline filtering."
	}

	return result
}

func validateConfig(cfg *Config) error {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = modeNewFindingsOnly
	}
	switch cfg.Mode {
	case modeOff, modeNewFindingsOnly:
	default:
		return fmt.Errorf("validate baseline: unsupported mode %q", cfg.Mode)
	}

	normalized := make([]string, 0, len(cfg.KnownFindingIDs))
	for _, id := range cfg.KnownFindingIDs {
		value := strings.TrimSpace(id)
		if value == "" {
			return fmt.Errorf("validate baseline: known_finding_ids contains empty value")
		}
		normalized = append(normalized, value)
	}
	cfg.KnownFindingIDs = normalized
	cfg.Version = strings.TrimSpace(cfg.Version)
	return nil
}
