package enforcement

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

type Config struct {
	Version                     string   `json:"version"`
	Phase                       string   `json:"phase"`
	ProtectedPaths              []string `json:"protected_paths"`
	BlockSeverities             []string `json:"block_severities"`
	RequireNoAbstainOnProtected bool     `json:"require_no_abstain_on_protected"`
}

type Decision struct {
	Phase               string   `json:"phase"`
	Status              string   `json:"status"`
	Reason              string   `json:"reason"`
	ProtectedPathChange bool     `json:"protected_path_change"`
	BlockingFindingIDs  []string `json:"blocking_finding_ids,omitempty"`
}

func Load(path string) (Config, error) {
	if path == "" {
		return defaultConfig(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read rollout config: %w", err)
	}
	cfg := defaultConfig()
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse rollout JSON: %w", err)
	}
	return cfg, nil
}

func Decide(cfg Config, result model.ReviewResult, changedFiles []model.ChangedFile) Decision {
	protected := hasProtectedPathChange(cfg.ProtectedPaths, changedFiles)
	blockingIDs := collectBlockingFindings(cfg.BlockSeverities, result.Findings)
	phase := strings.ToLower(strings.TrimSpace(cfg.Phase))

	switch phase {
	case "advisory":
		if len(result.Findings) > 0 {
			return Decision{
				Phase:               phase,
				Status:              "warn",
				Reason:              "advisory phase: findings reported but merge is not blocked",
				ProtectedPathChange: protected,
				BlockingFindingIDs:  blockingIDs,
			}
		}
		return Decision{Phase: phase, Status: "pass", Reason: "advisory phase: no findings", ProtectedPathChange: protected}

	case "enforced":
		if protected && len(blockingIDs) > 0 {
			return Decision{
				Phase:               phase,
				Status:              "block",
				Reason:              "blocking severities detected on protected-path changes",
				ProtectedPathChange: true,
				BlockingFindingIDs:  blockingIDs,
			}
		}
		if protected && cfg.RequireNoAbstainOnProtected && len(result.Abstain) > 0 {
			return Decision{
				Phase:               phase,
				Status:              "block",
				Reason:              "abstentions are disallowed for protected-path changes",
				ProtectedPathChange: true,
			}
		}
		if len(result.Findings) > 0 {
			return Decision{
				Phase:               phase,
				Status:              "warn",
				Reason:              "findings detected outside enforce block conditions",
				ProtectedPathChange: protected,
				BlockingFindingIDs:  blockingIDs,
			}
		}
		return Decision{Phase: phase, Status: "pass", Reason: "enforced phase: no blocking conditions met", ProtectedPathChange: protected}

	case "strict":
		if len(blockingIDs) > 0 {
			return Decision{
				Phase:               phase,
				Status:              "block",
				Reason:              "strict phase: blocking severities are not allowed",
				ProtectedPathChange: protected,
				BlockingFindingIDs:  blockingIDs,
			}
		}
		if len(result.Findings) > 0 {
			return Decision{
				Phase:               phase,
				Status:              "warn",
				Reason:              "strict phase: non-blocking findings present",
				ProtectedPathChange: protected,
			}
		}
		return Decision{Phase: phase, Status: "pass", Reason: "strict phase: no findings", ProtectedPathChange: protected}
	default:
		return Decision{Phase: phase, Status: "warn", Reason: "unknown phase; defaulting to advisory semantics", ProtectedPathChange: protected, BlockingFindingIDs: blockingIDs}
	}
}

func collectBlockingFindings(blockSeverities []string, findings []model.Finding) []string {
	allowed := map[string]struct{}{}
	for _, s := range blockSeverities {
		allowed[strings.ToUpper(strings.TrimSpace(s))] = struct{}{}
	}

	ids := make([]string, 0)
	for _, f := range findings {
		if _, ok := allowed[strings.ToUpper(strings.TrimSpace(f.Severity))]; ok {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

func hasProtectedPathChange(patterns []string, changedFiles []model.ChangedFile) bool {
	for _, changed := range changedFiles {
		for _, pattern := range patterns {
			if matchesPathPattern(pattern, changed.Filename) {
				return true
			}
		}
	}
	return false
}

func matchesPathPattern(pattern, file string) bool {
	normalizedPattern := normalizeRepoPath(pattern)
	normalizedFile := normalizeRepoPath(file)

	if strings.HasSuffix(normalizedPattern, "/**") {
		prefix := strings.TrimSuffix(normalizedPattern, "/**")
		prefix = strings.TrimSuffix(prefix, "/")
		return strings.HasPrefix(normalizedFile, prefix+"/") || normalizedFile == prefix
	}

	ok, err := path.Match(normalizedPattern, normalizedFile)
	if err != nil {
		return false
	}
	return ok
}

func normalizeRepoPath(value string) string {
	normalized := strings.TrimSpace(value)
	normalized = strings.ReplaceAll(normalized, "\\", "/")
	normalized = filepath.ToSlash(normalized)
	for strings.HasPrefix(normalized, "./") {
		normalized = strings.TrimPrefix(normalized, "./")
	}
	for strings.Contains(normalized, "//") {
		normalized = strings.ReplaceAll(normalized, "//", "/")
	}
	return normalized
}

func defaultConfig() Config {
	return Config{
		Version: "builtin-rollout-v1",
		Phase:   "advisory",
		ProtectedPaths: []string{
			".github/workflows/**",
			"deploy/**",
			"cmd/server/**",
			"internal/service/**",
			"internal/security/**",
		},
		BlockSeverities:             []string{"P0", "P1"},
		RequireNoAbstainOnProtected: false,
	}
}
