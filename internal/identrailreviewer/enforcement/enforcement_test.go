package enforcement

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func TestMatchesPathPatternNormalizesSlashDelimitedPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		file    string
		want    bool
	}{
		{
			name:    "recursive pattern matches windows style file path",
			pattern: "deploy/**",
			file:    `deploy\prod\values.yaml`,
			want:    true,
		},
		{
			name:    "single segment wildcard matches windows style file path",
			pattern: ".github/workflows/*",
			file:    `.github\workflows\ci.yml`,
			want:    true,
		},
		{
			name:    "normalized relative file path matches",
			pattern: "cmd/server/**",
			file:    `./cmd\server\main.go`,
			want:    true,
		},
		{
			name:    "non matching path returns false",
			pattern: "internal/security/**",
			file:    "internal/api/router.go",
			want:    false,
		},
		{
			name:    "invalid glob pattern fails closed",
			pattern: "internal/[",
			file:    "internal/a.go",
			want:    false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := matchesPathPattern(tc.pattern, tc.file)
			if got != tc.want {
				t.Fatalf("matchesPathPattern(%q, %q) = %v, want %v", tc.pattern, tc.file, got, tc.want)
			}
		})
	}
}

func TestDecideBlocksOnProtectedPathWithWindowsStyleChangedFile(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Phase:          "enforced",
		ProtectedPaths: []string{"deploy/**"},
		BlockSeverities: []string{
			"P0",
			"P1",
		},
	}

	result := model.ReviewResult{
		Findings: []model.Finding{
			{ID: "F-1", Severity: "P1"},
		},
	}

	decision := Decide(cfg, result, []model.ChangedFile{
		{Filename: `deploy\prod\service.yaml`},
	})

	if decision.Status != "block" {
		t.Fatalf("expected block decision, got %q", decision.Status)
	}
	if !decision.ProtectedPathChange {
		t.Fatal("expected protected path change to be true")
	}
	if len(decision.BlockingFindingIDs) != 1 || decision.BlockingFindingIDs[0] != "F-1" {
		t.Fatalf("unexpected blocking finding ids: %#v", decision.BlockingFindingIDs)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("empty path uses builtin defaults", func(t *testing.T) {
		t.Parallel()
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load(\"\") error: %v", err)
		}
		if cfg.Phase != "advisory" {
			t.Fatalf("expected default advisory phase, got %q", cfg.Phase)
		}
		if len(cfg.ProtectedPaths) == 0 || len(cfg.BlockSeverities) == 0 {
			t.Fatalf("expected non-empty default protected paths and block severities: %+v", cfg)
		}
	})

	t.Run("valid file overrides config", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		p := filepath.Join(dir, "rollout.json")
		payload := `{"version":"v1","phase":"strict","protected_paths":["internal/**"],"block_severities":["P0"],"require_no_abstain_on_protected":true}`
		if err := os.WriteFile(p, []byte(payload), 0o644); err != nil {
			t.Fatalf("write rollout config: %v", err)
		}
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("Load(valid file) error: %v", err)
		}
		if cfg.Phase != "strict" || !cfg.RequireNoAbstainOnProtected {
			t.Fatalf("expected parsed strict config, got %+v", cfg)
		}
	})

	t.Run("invalid file and json return errors", func(t *testing.T) {
		t.Parallel()
		if _, err := Load("definitely-missing-rollout.json"); err == nil {
			t.Fatal("expected read error for missing rollout file")
		}

		dir := t.TempDir()
		p := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
			t.Fatalf("write invalid json: %v", err)
		}
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "parse rollout JSON") {
			t.Fatalf("expected parse rollout JSON error, got %v", err)
		}
	})
}

func TestDecidePhasesAndFallback(t *testing.T) {
	t.Parallel()

	nonBlockingFinding := model.Finding{ID: "F-low", Severity: "P3"}
	blockingFinding := model.Finding{ID: "F-high", Severity: "P1"}

	tests := []struct {
		name        string
		cfg         Config
		result      model.ReviewResult
		changed     []model.ChangedFile
		wantStatus  string
		wantReason  string
		wantBlockID string
	}{
		{
			name:       "advisory with findings warns",
			cfg:        Config{Phase: "advisory", BlockSeverities: []string{"P1"}},
			result:     model.ReviewResult{Findings: []model.Finding{nonBlockingFinding}},
			wantStatus: "warn",
			wantReason: "advisory phase: findings reported but merge is not blocked",
		},
		{
			name:       "advisory without findings passes",
			cfg:        Config{Phase: "advisory"},
			result:     model.ReviewResult{},
			wantStatus: "pass",
			wantReason: "advisory phase: no findings",
		},
		{
			name: "enforced abstain on protected blocks",
			cfg: Config{
				Phase:                       "enforced",
				ProtectedPaths:              []string{"deploy/**"},
				BlockSeverities:             []string{"P1"},
				RequireNoAbstainOnProtected: true,
			},
			result: model.ReviewResult{
				Findings: []model.Finding{nonBlockingFinding},
				Abstain:  []string{"insufficient-context"},
			},
			changed:    []model.ChangedFile{{Filename: "deploy/app.yaml"}},
			wantStatus: "block",
			wantReason: "abstentions are disallowed for protected-path changes",
		},
		{
			name: "enforced findings outside block conditions warn",
			cfg: Config{
				Phase:          "enforced",
				ProtectedPaths: []string{"deploy/**"},
				BlockSeverities: []string{
					"P1",
				},
			},
			result:     model.ReviewResult{Findings: []model.Finding{nonBlockingFinding}},
			changed:    []model.ChangedFile{{Filename: "internal/api/router.go"}},
			wantStatus: "warn",
			wantReason: "findings detected outside enforce block conditions",
		},
		{
			name:       "enforced without findings passes",
			cfg:        Config{Phase: "enforced"},
			result:     model.ReviewResult{},
			wantStatus: "pass",
			wantReason: "enforced phase: no blocking conditions met",
		},
		{
			name:        "strict with blocking severity blocks",
			cfg:         Config{Phase: "strict", BlockSeverities: []string{"P1"}},
			result:      model.ReviewResult{Findings: []model.Finding{blockingFinding}},
			wantStatus:  "block",
			wantReason:  "strict phase: blocking severities are not allowed",
			wantBlockID: "F-high",
		},
		{
			name:       "strict with non-blocking finding warns",
			cfg:        Config{Phase: "strict", BlockSeverities: []string{"P0"}},
			result:     model.ReviewResult{Findings: []model.Finding{nonBlockingFinding}},
			wantStatus: "warn",
			wantReason: "strict phase: non-blocking findings present",
		},
		{
			name:       "strict with no findings passes",
			cfg:        Config{Phase: "strict"},
			result:     model.ReviewResult{},
			wantStatus: "pass",
			wantReason: "strict phase: no findings",
		},
		{
			name:        "unknown phase warns with fallback reason",
			cfg:         Config{Phase: "custom", BlockSeverities: []string{"P1"}},
			result:      model.ReviewResult{Findings: []model.Finding{blockingFinding}},
			wantStatus:  "warn",
			wantReason:  "unknown phase; defaulting to advisory semantics",
			wantBlockID: "F-high",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			decision := Decide(tc.cfg, tc.result, tc.changed)
			if decision.Status != tc.wantStatus {
				t.Fatalf("Decide status = %q, want %q", decision.Status, tc.wantStatus)
			}
			if decision.Reason != tc.wantReason {
				t.Fatalf("Decide reason = %q, want %q", decision.Reason, tc.wantReason)
			}
			if tc.wantBlockID != "" {
				if len(decision.BlockingFindingIDs) == 0 || decision.BlockingFindingIDs[0] != tc.wantBlockID {
					t.Fatalf("unexpected blocking ids: %#v", decision.BlockingFindingIDs)
				}
			}
		})
	}
}
