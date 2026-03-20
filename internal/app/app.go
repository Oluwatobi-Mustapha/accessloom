package app

import (
	"context"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// ScanResult bundles one collection and analysis cycle.
type ScanResult struct {
	Assets        int
	RawAssets     []providers.RawAsset
	SourceErrors  []providers.SourceError
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
	tracer := otel.Tracer("identrail/scanner")
	ctx, span := tracer.Start(ctx, "scanner.run")
	defer span.End()

	var (
		raw          []providers.RawAsset
		sourceErrors []providers.SourceError
		err          error
	)
	collectCtx, collectSpan := tracer.Start(ctx, "scanner.collect")
	if diagnosticCollector, ok := s.Collector.(providers.DiagnosticCollector); ok {
		raw, sourceErrors, err = diagnosticCollector.CollectWithDiagnostics(collectCtx)
	} else {
		raw, err = s.Collector.Collect(collectCtx)
	}
	collectSpan.SetAttributes(
		attribute.Int("raw_assets", len(raw)),
		attribute.Int("source_errors", len(sourceErrors)),
	)
	if err != nil {
		collectSpan.RecordError(err)
		collectSpan.SetStatus(codes.Error, "collector failed")
	}
	collectSpan.End()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "collector failed")
		return ScanResult{}, err
	}

	normalizeCtx, normalizeSpan := tracer.Start(ctx, "scanner.normalize")
	bundle, err := s.Normalizer.Normalize(normalizeCtx, raw)
	if err != nil {
		normalizeSpan.RecordError(err)
		normalizeSpan.SetStatus(codes.Error, "normalizer failed")
	}
	normalizeSpan.SetAttributes(
		attribute.Int("identities", len(bundle.Identities)),
		attribute.Int("workloads", len(bundle.Workloads)),
		attribute.Int("policies", len(bundle.Policies)),
	)
	normalizeSpan.End()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "normalizer failed")
		return ScanResult{}, err
	}
	if err := providers.ValidateNormalizedBundle(bundle); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "normalized bundle validation failed")
		return ScanResult{}, err
	}

	permissionCtx, permissionSpan := tracer.Start(ctx, "scanner.permissions")
	permissions, err := s.PermissionResolver.ResolvePermissions(permissionCtx, bundle)
	if err != nil {
		permissionSpan.RecordError(err)
		permissionSpan.SetStatus(codes.Error, "permission resolver failed")
	}
	permissionSpan.SetAttributes(attribute.Int("permissions", len(permissions)))
	permissionSpan.End()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "permission resolver failed")
		return ScanResult{}, err
	}

	relationshipCtx, relationshipSpan := tracer.Start(ctx, "scanner.relationships")
	relationships, err := s.RelationshipResolver.ResolveRelationships(relationshipCtx, bundle, permissions)
	if err != nil {
		relationshipSpan.RecordError(err)
		relationshipSpan.SetStatus(codes.Error, "relationship resolver failed")
	}
	relationshipSpan.SetAttributes(attribute.Int("relationships", len(relationships)))
	relationshipSpan.End()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "relationship resolver failed")
		return ScanResult{}, err
	}
	if err := providers.ValidateGraphContract(bundle, relationships); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "graph contract validation failed")
		return ScanResult{}, err
	}

	riskCtx, riskSpan := tracer.Start(ctx, "scanner.risk")
	findings, err := s.RiskRuleSet.Evaluate(riskCtx, bundle, relationships)
	if err != nil {
		riskSpan.RecordError(err)
		riskSpan.SetStatus(codes.Error, "risk rule evaluation failed")
	}
	riskSpan.SetAttributes(attribute.Int("findings", len(findings)))
	riskSpan.End()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "risk rule evaluation failed")
		return ScanResult{}, err
	}

	return ScanResult{
		Assets:        len(raw),
		RawAssets:     raw,
		SourceErrors:  sourceErrors,
		Bundle:        bundle,
		Permissions:   permissions,
		Relationships: relationships,
		Findings:      findings,
		Completed:     time.Now().UTC(),
	}, nil
}
