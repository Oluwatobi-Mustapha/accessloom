package enforcement

import (
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
