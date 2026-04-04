package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

type Config struct {
	Version         string              `json:"version"`
	Confidence      confidenceThreshold `json:"confidence"`
	AbstainBelow    float64             `json:"abstain_below"`
	RequireEvidence bool                `json:"require_evidence"`
	RequiredFields  []string            `json:"required_fields"`
}

type confidenceThreshold struct {
	P0Min float64 `json:"p0_min"`
	P1Min float64 `json:"p1_min"`
	P2Min float64 `json:"p2_min"`
	P3Min float64 `json:"p3_min"`
}

var allowedRequiredFields = map[string]struct{}{
	"id":             {},
	"severity":       {},
	"confidence":     {},
	"rule_id":        {},
	"summary":        {},
	"rationale":      {},
	"file":           {},
	"line":           {},
	"recommendation": {},
}

func Load(path string) (Config, error) {
	if path == "" {
		return defaultConfig(), nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read policy: %w", err)
	}

	cfg := defaultConfig()
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse policy JSON: %w", err)
	}
	requiredFields, err := normalizeRequiredFields(cfg.RequiredFields)
	if err != nil {
		return Config{}, fmt.Errorf("validate policy: %w", err)
	}
	cfg.RequiredFields = requiredFields
	return cfg, nil
}

func Apply(cfg Config, result model.ReviewResult) model.ReviewResult {
	filtered := make([]model.Finding, 0, len(result.Findings))
	abstentions := append([]string{}, result.Abstain...)
	suppressed := 0

	for _, finding := range result.Findings {
		if cfg.RequireEvidence && !hasRequiredFields(finding, cfg.RequiredFields) {
			suppressed++
			abstentions = append(abstentions, fmt.Sprintf("suppressed %s: incomplete evidence fields", finding.ID))
			continue
		}

		requiredConfidence := minConfidence(cfg, finding.Severity)
		if finding.Confidence < requiredConfidence {
			suppressed++
			abstentions = append(abstentions, fmt.Sprintf("suppressed %s: confidence %.2f below %.2f", finding.ID, finding.Confidence, requiredConfidence))
			continue
		}

		filtered = append(filtered, finding)
	}

	result.Findings = filtered
	result.Abstain = abstentions
	if result.Metadata == nil {
		result.Metadata = map[string]string{}
	}
	result.Metadata["policy_version"] = cfg.Version
	result.Metadata["suppressed_findings"] = fmt.Sprintf("%d", suppressed)

	if len(filtered) == 0 && len(abstentions) > 0 {
		result.Status = "abstain"
		if suppressed > 0 {
			result.Summary = "Findings were suppressed by policy thresholds or evidence requirements."
		}
	} else if len(filtered) > 0 {
		result.Status = "findings"
		result.Summary = fmt.Sprintf("Detected %d deterministic finding(s) after policy filtering.", len(filtered))
	} else {
		result.Status = "clean"
		result.Summary = "No deterministic findings after policy filtering."
	}

	return result
}

func minConfidence(cfg Config, severity string) float64 {
	threshold := cfg.AbstainBelow
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "P0":
		if cfg.Confidence.P0Min > threshold {
			threshold = cfg.Confidence.P0Min
		}
	case "P1":
		if cfg.Confidence.P1Min > threshold {
			threshold = cfg.Confidence.P1Min
		}
	case "P2":
		if cfg.Confidence.P2Min > threshold {
			threshold = cfg.Confidence.P2Min
		}
	case "P3":
		if cfg.Confidence.P3Min > threshold {
			threshold = cfg.Confidence.P3Min
		}
	}
	return threshold
}

func hasRequiredFields(f model.Finding, fields []string) bool {
	for _, field := range fields {
		switch strings.ToLower(strings.TrimSpace(field)) {
		case "id":
			if strings.TrimSpace(f.ID) == "" {
				return false
			}
		case "severity":
			if strings.TrimSpace(f.Severity) == "" {
				return false
			}
		case "confidence":
			if f.Confidence <= 0 || f.Confidence > 1 {
				return false
			}
		case "rule_id":
			if strings.TrimSpace(f.RuleID) == "" {
				return false
			}
		case "summary":
			if strings.TrimSpace(f.Summary) == "" {
				return false
			}
		case "rationale":
			if strings.TrimSpace(f.Rationale) == "" {
				return false
			}
		case "file":
			if strings.TrimSpace(f.File) == "" {
				return false
			}
		case "line":
			if f.Line <= 0 {
				return false
			}
		case "recommendation":
			if strings.TrimSpace(f.Recommendation) == "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func normalizeRequiredFields(fields []string) ([]string, error) {
	normalized := make([]string, 0, len(fields))
	for _, field := range fields {
		value := strings.ToLower(strings.TrimSpace(field))
		if value == "" {
			return nil, fmt.Errorf("required_fields contains empty field name")
		}
		if _, ok := allowedRequiredFields[value]; !ok {
			return nil, fmt.Errorf("required_fields contains unknown field %q", field)
		}
		normalized = append(normalized, value)
	}
	return normalized, nil
}

func defaultConfig() Config {
	return Config{
		Version: "builtin-v1",
		Confidence: confidenceThreshold{
			P0Min: 0.95,
			P1Min: 0.90,
			P2Min: 0.82,
			P3Min: 0.75,
		},
		AbstainBelow:    0.80,
		RequireEvidence: true,
		RequiredFields: []string{
			"id",
			"severity",
			"confidence",
			"rule_id",
			"summary",
			"rationale",
			"file",
			"line",
			"recommendation",
		},
	}
}
