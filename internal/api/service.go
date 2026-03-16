package api

import (
	"context"
	"errors"
	"fmt"
	"sort"
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

// ErrScanInProgress is returned when a scan for the same provider is already running.
var ErrScanInProgress = errors.New("scan already in progress")

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
	s.appendScanEvent(ctx, record.ID, "info", "scan started", map[string]any{"provider": s.Provider})

	result, err := s.Scanner.Run(ctx)
	if err != nil {
		s.appendScanEvent(ctx, record.ID, "error", "scan failed during collection/analysis", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, err.Error())
		return RunScanResult{}, err
	}

	if err := s.Store.UpsertArtifacts(ctx, record.ID, db.ScanArtifacts{
		RawAssets:     result.RawAssets,
		Bundle:        result.Bundle,
		Permissions:   result.Permissions,
		Relationships: result.Relationships,
	}); err != nil {
		s.appendScanEvent(ctx, record.ID, "error", "scan failed while persisting artifacts", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist artifacts: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, "info", "artifacts persisted", map[string]any{"raw_assets": len(result.RawAssets), "identities": len(result.Bundle.Identities)})

	if err := s.Store.UpsertFindings(ctx, record.ID, result.Findings); err != nil {
		s.appendScanEvent(ctx, record.ID, "error", "scan failed while persisting findings", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist findings: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, "info", "findings persisted", map[string]any{"findings": len(result.Findings)})

	if err := s.Store.CompleteScan(ctx, record.ID, "completed", s.Now().UTC(), result.Assets, len(result.Findings), ""); err != nil {
		s.appendScanEvent(ctx, record.ID, "error", "scan failed while finalizing scan record", map[string]any{"error": err.Error()})
		return RunScanResult{}, fmt.Errorf("complete scan record: %w", err)
	}

	record.Status = "completed"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.AssetCount = result.Assets
	record.FindingCount = len(result.Findings)
	s.appendScanEvent(ctx, record.ID, "info", "scan completed", map[string]any{"assets": result.Assets, "findings": len(result.Findings)})
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
	return s.Store.ListScanEvents(ctx, scanID, limit)
}

// GetScanDiff compares findings between this scan and previous scan of same provider.
func (s *Service) GetScanDiff(ctx context.Context, scanID string, limit int) (ScanDiff, error) {
	currentScan, err := s.Store.GetScan(ctx, scanID)
	if err != nil {
		return ScanDiff{}, err
	}

	currentFindings, err := s.Store.ListFindingsByScan(ctx, scanID, 5000)
	if err != nil {
		return ScanDiff{}, err
	}
	previousScanID := ""
	scans, err := s.Store.ListScans(ctx, 500)
	if err != nil {
		return ScanDiff{}, err
	}
	for _, scan := range scans {
		if scan.ID == currentScan.ID || scan.Provider != currentScan.Provider {
			continue
		}
		if scan.StartedAt.Before(currentScan.StartedAt) {
			previousScanID = scan.ID
			break
		}
	}

	diff := ScanDiff{ScanID: scanID, PreviousScanID: previousScanID}
	currentByID := map[string]domain.Finding{}
	for _, finding := range currentFindings {
		currentByID[finding.ID] = finding
	}
	if previousScanID == "" {
		diff.Added = currentFindings
		diff.AddedCount = len(currentFindings)
		diff.applyLimit(limit)
		return diff, nil
	}

	previousFindings, err := s.Store.ListFindingsByScan(ctx, previousScanID, 5000)
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
