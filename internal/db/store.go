package db

import (
	"context"
	"errors"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// ErrNotFound indicates the requested record does not exist.
var ErrNotFound = errors.New("record not found")

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

// ScanArtifacts contains raw and normalized scan outputs to persist idempotently.
type ScanArtifacts struct {
	RawAssets     []providers.RawAsset
	Bundle        providers.NormalizedBundle
	Permissions   []providers.PermissionTuple
	Relationships []domain.Relationship
}

// ScanEvent tracks important state transitions for scan observability.
type ScanEvent struct {
	ID        string         `json:"id"`
	ScanID    string         `json:"scan_id"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// Store defines persistence operations required by API and scheduler orchestration.
type Store interface {
	CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error)
	GetScan(ctx context.Context, scanID string) (ScanRecord, error)
	CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error
	UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error
	UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error
	ListScans(ctx context.Context, limit int) ([]ScanRecord, error)
	ListFindings(ctx context.Context, limit int) ([]domain.Finding, error)
	ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error)
	AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error
	ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error)
	Close() error
}
