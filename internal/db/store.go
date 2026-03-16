package db

import (
	"context"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

// ScanRecord tracks persisted scan execution metadata.
type ScanRecord struct {
	ID           string     `json:"id"`
	Provider     string     `json:"provider"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	AssetCount   int        `json:"asset_count"`
	FindingCount int        `json:"finding_count"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// Store defines persistence operations required by API and scheduler orchestration.
type Store interface {
	CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error)
	CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error
	UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error
	ListScans(ctx context.Context, limit int) ([]ScanRecord, error)
	ListFindings(ctx context.Context, limit int) ([]domain.Finding, error)
	Close() error
}
