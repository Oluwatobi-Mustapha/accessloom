package app

import (
	"context"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// ScanResult bundles one collection and analysis cycle.
type ScanResult struct {
	Assets        int
	RawAssets     []providers.RawAsset
	Bundle        providers.NormalizedBundle
	Permissions   []providers.PermissionTuple
	Relationships []domain.Relationship
	Findings      []domain.Finding
	Completed     time.Time
}

// Scanner orchestrates end-to-end scan stages with explicit dependencies.
type Scanner struct {
	Collector            providers.Collector
	Normalizer           providers.Normalizer
	PermissionResolver   providers.PermissionResolver
	RelationshipResolver providers.RelationshipResolver
	RiskRuleSet          providers.RiskRuleSet
}

// Run executes a deterministic scan pipeline. Each dependency is injected so
// provider modules can evolve independently while keeping orchestration stable.
func (s Scanner) Run(ctx context.Context) (ScanResult, error) {
	raw, err := s.Collector.Collect(ctx)
	if err != nil {
		return ScanResult{}, err
	}

	bundle, err := s.Normalizer.Normalize(ctx, raw)
	if err != nil {
		return ScanResult{}, err
	}

	permissions, err := s.PermissionResolver.ResolvePermissions(ctx, bundle)
	if err != nil {
		return ScanResult{}, err
	}

	relationships, err := s.RelationshipResolver.ResolveRelationships(ctx, bundle, permissions)
	if err != nil {
		return ScanResult{}, err
	}

	findings, err := s.RiskRuleSet.Evaluate(ctx, bundle, relationships)
	if err != nil {
		return ScanResult{}, err
	}

	return ScanResult{
		Assets:        len(raw),
		RawAssets:     raw,
		Bundle:        bundle,
		Permissions:   permissions,
		Relationships: relationships,
		Findings:      findings,
		Completed:     time.Now().UTC(),
	}, nil
}
