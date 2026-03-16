package api

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
)

// ScannerRunner is the scan execution dependency required by API service.
type ScannerRunner interface {
	Run(ctx context.Context) (app.ScanResult, error)
}

// Service orchestrates scan execution and persistence.
type Service struct {
	Store        db.Store
	Scanner      ScannerRunner
	Provider     string
	Now          func() time.Time
	Locker       scheduler.Locker
	Alerter      FindingAlerter
	OnAlertError func(error)
}

// RunScanResult is returned after a scan API trigger.
type RunScanResult struct {
	Scan         db.ScanRecord `json:"scan"`
	Assets       int           `json:"assets"`
	FindingCount int           `json:"finding_count"`
}

// FindingsFilter narrows findings list queries without changing API response schema.
type FindingsFilter struct {
	ScanID   string
	Severity string
	Type     string
}

// FindingsSummary returns quick aggregation counters for dashboards/alerts.
type FindingsSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
}

// ScanDiff captures delta between one scan and its previous scan for same provider.
type ScanDiff struct {
	ScanID          string           `json:"scan_id"`
	PreviousScanID  string           `json:"previous_scan_id,omitempty"`
	AddedCount      int              `json:"added_count"`
	ResolvedCount   int              `json:"resolved_count"`
	PersistingCount int              `json:"persisting_count"`
	Added           []domain.Finding `json:"added"`
	Resolved        []domain.Finding `json:"resolved"`
	Persisting      []domain.Finding `json:"persisting"`
}

// TrendPoint gives one scan-level snapshot used by dashboard trend charts.
type TrendPoint struct {
	ScanID     string         `json:"scan_id"`
	StartedAt  time.Time      `json:"started_at"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

// ErrScanInProgress is returned when a scan for the same provider is already running.
var ErrScanInProgress = errors.New("scan already in progress")

// ErrInvalidScanDiffBaseline is returned when previous_scan_id is incompatible.
var ErrInvalidScanDiffBaseline = errors.New("invalid scan diff baseline")

// NewService creates an API service with defaults.
func NewService(store db.Store, scanner ScannerRunner, provider string) *Service {
	return &Service{
		Store:    store,
		Scanner:  scanner,
		Provider: provider,
		Now:      time.Now,
		Locker:   scheduler.NewInMemoryLocker(),
		Alerter:  NopFindingAlerter{},
	}
}

// RunScan executes one scan and persists metadata + findings.
func (s *Service) RunScan(ctx context.Context) (RunScanResult, error) {
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire("scan:" + s.Provider)
		if !ok {
			return RunScanResult{}, ErrScanInProgress
		}
		defer release()
	}

	started := s.Now().UTC()
	record, err := s.Store.CreateScan(ctx, s.Provider, started)
	if err != nil {
		return RunScanResult{}, err
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan started", map[string]any{"provider": s.Provider})

	result, err := s.Scanner.Run(ctx)
	if err != nil {
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed during collection/analysis", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, err.Error())
		return RunScanResult{}, err
	}

	if err := s.Store.UpsertArtifacts(ctx, record.ID, db.ScanArtifacts{
		RawAssets:     result.RawAssets,
		Bundle:        result.Bundle,
		Permissions:   result.Permissions,
		Relationships: result.Relationships,
	}); err != nil {
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed while persisting artifacts", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist artifacts: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "artifacts persisted", map[string]any{"raw_assets": len(result.RawAssets), "identities": len(result.Bundle.Identities)})

	if err := s.Store.UpsertFindings(ctx, record.ID, result.Findings); err != nil {
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed while persisting findings", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist findings: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "findings persisted", map[string]any{"findings": len(result.Findings)})

	if err := s.Store.CompleteScan(ctx, record.ID, "completed", s.Now().UTC(), result.Assets, len(result.Findings), ""); err != nil {
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed while finalizing scan record", map[string]any{"error": err.Error()})
		return RunScanResult{}, fmt.Errorf("complete scan record: %w", err)
	}

	record.Status = "completed"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.AssetCount = result.Assets
	record.FindingCount = len(result.Findings)
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan completed", map[string]any{"assets": result.Assets, "findings": len(result.Findings)})
	if s.Alerter != nil {
		if alertErr := s.Alerter.NotifyScan(ctx, s.Provider, record, result.Findings); alertErr != nil && s.OnAlertError != nil {
			s.OnAlertError(alertErr)
		}
	}

	return RunScanResult{
		Scan:         record,
		Assets:       result.Assets,
		FindingCount: len(result.Findings),
	}, nil
}

// ListFindings returns persisted findings.
func (s *Service) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	return s.Store.ListFindings(ctx, limit)
}

// ListFindingsFiltered returns findings with optional scan/type/severity filters.
func (s *Service) ListFindingsFiltered(ctx context.Context, limit int, filter FindingsFilter) ([]domain.Finding, error) {
	if strings.TrimSpace(filter.ScanID) == "" && strings.TrimSpace(filter.Severity) == "" && strings.TrimSpace(filter.Type) == "" {
		return s.Store.ListFindings(ctx, limit)
	}

	loadLimit := limit
	if loadLimit <= 0 {
		loadLimit = 100
	}
	if loadLimit < 5000 {
		loadLimit = 5000
	}

	var source []domain.Finding
	var err error
	if strings.TrimSpace(filter.ScanID) != "" {
		source, err = s.Store.ListFindingsByScan(ctx, strings.TrimSpace(filter.ScanID), loadLimit)
	} else {
		source, err = s.Store.ListFindings(ctx, loadLimit)
	}
	if err != nil {
		return nil, err
	}

	severity := strings.ToLower(strings.TrimSpace(filter.Severity))
	findingType := strings.ToLower(strings.TrimSpace(filter.Type))
	result := make([]domain.Finding, 0, len(source))
	for _, item := range source {
		if severity != "" && strings.ToLower(string(item.Severity)) != severity {
			continue
		}
		if findingType != "" && strings.ToLower(string(item.Type)) != findingType {
			continue
		}
		result = append(result, item)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result, nil
}

// GetFinding returns one finding by id, optionally scoped to one scan.
func (s *Service) GetFinding(ctx context.Context, findingID string, scanID string) (domain.Finding, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return domain.Finding{}, db.ErrNotFound
	}
	filtered, err := s.ListFindingsFiltered(ctx, 5000, FindingsFilter{ScanID: strings.TrimSpace(scanID)})
	if err != nil {
		return domain.Finding{}, err
	}
	for _, item := range filtered {
		if item.ID == id {
			return item, nil
		}
	}
	return domain.Finding{}, db.ErrNotFound
}

// ListScans returns persisted scans.
func (s *Service) ListScans(ctx context.Context, limit int) ([]db.ScanRecord, error) {
	return s.Store.ListScans(ctx, limit)
}

// GetFindingsSummary returns grouped counts by severity and type.
func (s *Service) GetFindingsSummary(ctx context.Context, limit int) (FindingsSummary, error) {
	items, err := s.Store.ListFindings(ctx, limit)
	if err != nil {
		return FindingsSummary{}, err
	}
	summary := FindingsSummary{
		Total:      len(items),
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
	}
	for _, item := range items {
		summary.BySeverity[string(item.Severity)]++
		summary.ByType[string(item.Type)]++
	}
	return summary, nil
}

// ListScanEvents returns recent scan events for one scan id.
func (s *Service) ListScanEvents(ctx context.Context, scanID string, limit int) ([]db.ScanEvent, error) {
	return s.ListScanEventsFiltered(ctx, scanID, "", limit)
}

// ListScanEventsFiltered returns recent scan events with optional level filtering.
func (s *Service) ListScanEventsFiltered(ctx context.Context, scanID string, level string, limit int) ([]db.ScanEvent, error) {
	events, err := s.Store.ListScanEvents(ctx, scanID, limit)
	if err != nil {
		return nil, err
	}
	normalizedLevel := strings.ToLower(strings.TrimSpace(level))
	if normalizedLevel == "" {
		return events, nil
	}
	result := make([]db.ScanEvent, 0, len(events))
	for _, event := range events {
		if strings.ToLower(strings.TrimSpace(event.Level)) != normalizedLevel {
			continue
		}
		result = append(result, event)
	}
	return result, nil
}

// ListIdentities returns identities for given filters, defaulting scan_id to latest scan.
func (s *Service) ListIdentities(ctx context.Context, scanID string, provider string, identityType string, namePrefix string, limit int) ([]domain.Identity, error) {
	normalizedScanID := scanID
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	return s.Store.ListIdentities(ctx, db.IdentityFilter{
		ScanID:     normalizedScanID,
		Provider:   provider,
		Type:       identityType,
		NamePrefix: namePrefix,
	}, limit)
}

// ListRelationships returns relationships for given filters, defaulting scan_id to latest scan.
func (s *Service) ListRelationships(ctx context.Context, scanID string, relationshipType string, fromNodeID string, toNodeID string, limit int) ([]domain.Relationship, error) {
	normalizedScanID := scanID
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	return s.Store.ListRelationships(ctx, db.RelationshipFilter{
		ScanID:     normalizedScanID,
		Type:       relationshipType,
		FromNodeID: fromNodeID,
		ToNodeID:   toNodeID,
	}, limit)
}

// GetFindingsTrend returns findings totals by severity across recent scans.
func (s *Service) GetFindingsTrend(ctx context.Context, points int) ([]TrendPoint, error) {
	return s.GetFindingsTrendFiltered(ctx, points, "", "")
}

// GetFindingsTrendFiltered returns findings trend with optional severity/type filters.
func (s *Service) GetFindingsTrendFiltered(ctx context.Context, points int, severity string, findingType string) ([]TrendPoint, error) {
	if points <= 0 {
		points = 10
	}
	scans, err := s.Store.ListScans(ctx, points)
	if err != nil {
		return nil, err
	}
	// Return oldest->newest for chart consumers.
	sort.Slice(scans, func(i, j int) bool { return scans[i].StartedAt.Before(scans[j].StartedAt) })
	result := make([]TrendPoint, 0, len(scans))
	normalizedSeverity := strings.ToLower(strings.TrimSpace(severity))
	normalizedType := strings.ToLower(strings.TrimSpace(findingType))
	for _, scan := range scans {
		findings, err := s.Store.ListFindingsByScan(ctx, scan.ID, 5000)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			return nil, err
		}
		point := TrendPoint{
			ScanID:     scan.ID,
			StartedAt:  scan.StartedAt,
			BySeverity: map[string]int{},
		}
		for _, finding := range findings {
			if normalizedSeverity != "" && strings.ToLower(string(finding.Severity)) != normalizedSeverity {
				continue
			}
			if normalizedType != "" && strings.ToLower(string(finding.Type)) != normalizedType {
				continue
			}
			point.BySeverity[string(finding.Severity)]++
			point.Total++
		}
		result = append(result, point)
	}
	return result, nil
}

// GetScanDiff compares findings between this scan and previous scan of same provider.
func (s *Service) GetScanDiff(ctx context.Context, scanID string, limit int) (ScanDiff, error) {
	return s.GetScanDiffAgainst(ctx, scanID, "", limit)
}

// GetScanDiffAgainst compares findings between one scan and an optional baseline scan.
func (s *Service) GetScanDiffAgainst(ctx context.Context, scanID string, previousScanID string, limit int) (ScanDiff, error) {
	currentScan, err := s.Store.GetScan(ctx, scanID)
	if err != nil {
		return ScanDiff{}, err
	}

	currentFindings, err := s.Store.ListFindingsByScan(ctx, scanID, 5000)
	if err != nil {
		return ScanDiff{}, err
	}
	normalizedPreviousScanID := strings.TrimSpace(previousScanID)
	if normalizedPreviousScanID != "" {
		if normalizedPreviousScanID == currentScan.ID {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
		baselineScan, err := s.Store.GetScan(ctx, normalizedPreviousScanID)
		if err != nil {
			return ScanDiff{}, err
		}
		if baselineScan.Provider != currentScan.Provider {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
		if !baselineScan.StartedAt.Before(currentScan.StartedAt) {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
	} else {
		scans, err := s.Store.ListScans(ctx, 500)
		if err != nil {
			return ScanDiff{}, err
		}
		for _, scan := range scans {
			if scan.ID == currentScan.ID || scan.Provider != currentScan.Provider {
				continue
			}
			if scan.StartedAt.Before(currentScan.StartedAt) {
				normalizedPreviousScanID = scan.ID
				break
			}
		}
	}

	diff := ScanDiff{ScanID: scanID, PreviousScanID: normalizedPreviousScanID}
	currentByID := map[string]domain.Finding{}
	for _, finding := range currentFindings {
		currentByID[finding.ID] = finding
	}
	if normalizedPreviousScanID == "" {
		diff.Added = currentFindings
		diff.AddedCount = len(currentFindings)
		diff.applyLimit(limit)
		return diff, nil
	}

	previousFindings, err := s.Store.ListFindingsByScan(ctx, normalizedPreviousScanID, 5000)
	if err != nil {
		return ScanDiff{}, err
	}
	previousByID := map[string]domain.Finding{}
	for _, finding := range previousFindings {
		previousByID[finding.ID] = finding
	}

	for id, finding := range currentByID {
		if _, exists := previousByID[id]; exists {
			diff.Persisting = append(diff.Persisting, finding)
			continue
		}
		diff.Added = append(diff.Added, finding)
	}
	for id, finding := range previousByID {
		if _, exists := currentByID[id]; exists {
			continue
		}
		diff.Resolved = append(diff.Resolved, finding)
	}

	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].CreatedAt.After(diff.Added[j].CreatedAt) })
	sort.Slice(diff.Resolved, func(i, j int) bool { return diff.Resolved[i].CreatedAt.After(diff.Resolved[j].CreatedAt) })
	sort.Slice(diff.Persisting, func(i, j int) bool { return diff.Persisting[i].CreatedAt.After(diff.Persisting[j].CreatedAt) })
	diff.AddedCount = len(diff.Added)
	diff.ResolvedCount = len(diff.Resolved)
	diff.PersistingCount = len(diff.Persisting)
	diff.applyLimit(limit)
	return diff, nil
}

func (s *Service) appendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) {
	_ = s.Store.AppendScanEvent(ctx, scanID, level, message, metadata)
}

func (d *ScanDiff) applyLimit(limit int) {
	if limit <= 0 {
		return
	}
	if len(d.Added) > limit {
		d.Added = d.Added[:limit]
	}
	if len(d.Resolved) > limit {
		d.Resolved = d.Resolved[:limit]
	}
	if len(d.Persisting) > limit {
		d.Persisting = d.Persisting[:limit]
	}
}

func (s *Service) latestScanID(ctx context.Context) (string, error) {
	scans, err := s.Store.ListScans(ctx, 1)
	if err != nil {
		return "", err
	}
	if len(scans) == 0 {
		return "", db.ErrNotFound
	}
	return scans[0].ID, nil
}
