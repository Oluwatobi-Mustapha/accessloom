package api

import (
	"context"
	"errors"
	"fmt"
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
	Store    db.Store
	Scanner  ScannerRunner
	Provider string
	Now      func() time.Time
	Locker   scheduler.Locker
}

// RunScanResult is returned after a scan API trigger.
type RunScanResult struct {
	Scan         db.ScanRecord `json:"scan"`
	Assets       int           `json:"assets"`
	FindingCount int           `json:"finding_count"`
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

	result, err := s.Scanner.Run(ctx)
	if err != nil {
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, err.Error())
		return RunScanResult{}, err
	}

	if err := s.Store.UpsertArtifacts(ctx, record.ID, db.ScanArtifacts{
		RawAssets:     result.RawAssets,
		Bundle:        result.Bundle,
		Permissions:   result.Permissions,
		Relationships: result.Relationships,
	}); err != nil {
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist artifacts: %w", err)
	}

	if err := s.Store.UpsertFindings(ctx, record.ID, result.Findings); err != nil {
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist findings: %w", err)
	}

	if err := s.Store.CompleteScan(ctx, record.ID, "completed", s.Now().UTC(), result.Assets, len(result.Findings), ""); err != nil {
		return RunScanResult{}, fmt.Errorf("complete scan record: %w", err)
	}

	record.Status = "completed"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.AssetCount = result.Assets
	record.FindingCount = len(result.Findings)

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
