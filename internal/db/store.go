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

// ErrScopeRequired indicates tenant/workspace scope must be provided in context.
var ErrScopeRequired = errors.New("scope is required")

const (
	ScanEventLevelDebug = "debug"
	ScanEventLevelInfo  = "info"
	ScanEventLevelWarn  = "warn"
	ScanEventLevelError = "error"

	FindingTriageActionAcknowledged = "acknowledged"
	FindingTriageActionSuppressed   = "suppressed"
	FindingTriageActionResolved     = "resolved"
	FindingTriageActionReopened     = "reopened"
	FindingTriageActionAssigned     = "assignee_updated"
	FindingTriageActionSuppression  = "suppression_updated"
	FindingTriageActionCommented    = "commented"
)

// ScanRecord tracks persisted scan execution metadata.
type ScanRecord struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"-"`
	WorkspaceID  string     `json:"-"`
	Provider     string     `json:"provider"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	AssetCount   int        `json:"asset_count"`
	FindingCount int        `json:"finding_count"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// RepoScanRecord tracks persisted repository exposure scan metadata.
type RepoScanRecord struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"-"`
	WorkspaceID    string     `json:"-"`
	Repository     string     `json:"repository"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	CommitsScanned int        `json:"commits_scanned"`
	FilesScanned   int        `json:"files_scanned"`
	FindingCount   int        `json:"finding_count"`
	Truncated      bool       `json:"truncated"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	HistoryLimit   int        `json:"-"`
	MaxFindings    int        `json:"-"`
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

// FindingTriageState stores mutable workflow metadata for one finding id.
type FindingTriageState struct {
	FindingID            string                        `json:"finding_id"`
	Status               domain.FindingLifecycleStatus `json:"status"`
	Assignee             string                        `json:"assignee,omitempty"`
	SuppressionExpiresAt *time.Time                    `json:"suppression_expires_at,omitempty"`
	UpdatedAt            time.Time                     `json:"updated_at"`
	UpdatedBy            string                        `json:"updated_by,omitempty"`
}

// FindingTriageEvent records one immutable workflow action.
type FindingTriageEvent struct {
	ID                   string                        `json:"id"`
	FindingID            string                        `json:"finding_id"`
	Action               string                        `json:"action"`
	FromStatus           domain.FindingLifecycleStatus `json:"from_status"`
	ToStatus             domain.FindingLifecycleStatus `json:"to_status"`
	Assignee             string                        `json:"assignee,omitempty"`
	SuppressionExpiresAt *time.Time                    `json:"suppression_expires_at,omitempty"`
	Comment              string                        `json:"comment,omitempty"`
	Actor                string                        `json:"actor,omitempty"`
	CreatedAt            time.Time                     `json:"created_at"`
}

// NormalizeScanEventLevel validates and normalizes event levels.
func NormalizeScanEventLevel(level string) (string, error) {
	switch level {
	case ScanEventLevelDebug, ScanEventLevelInfo, ScanEventLevelWarn, ScanEventLevelError:
		return level, nil
	default:
		return "", errors.New("invalid scan event level")
	}
}

// IdentityFilter controls identity list query shape.
type IdentityFilter struct {
	ScanID     string
	Provider   string
	Type       string
	NamePrefix string
}

// RelationshipFilter controls relationship list query shape.
type RelationshipFilter struct {
	ScanID     string
	Type       string
	FromNodeID string
	ToNodeID   string
}

// RepoFindingFilter controls repository finding list queries.
type RepoFindingFilter struct {
	RepoScanID string
	Severity   string
	Type       string
}

// Store defines persistence operations required by API and scheduler orchestration.
type Store interface {
	CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error)
	CreateQueuedScan(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error)
	ClaimNextQueuedScan(ctx context.Context, provider string) (ScanRecord, error)
	CountQueuedScans(ctx context.Context, provider string) (int, error)
	GetScan(ctx context.Context, scanID string) (ScanRecord, error)
	CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error
	UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error
	UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error
	GetFindingTriageState(ctx context.Context, findingID string) (FindingTriageState, error)
	ListFindingTriageStates(ctx context.Context, findingIDs []string) ([]FindingTriageState, error)
	UpsertFindingTriageState(ctx context.Context, state FindingTriageState) error
	AppendFindingTriageEvent(ctx context.Context, event FindingTriageEvent) error
	ApplyFindingTriageTransition(ctx context.Context, state FindingTriageState, event FindingTriageEvent) error
	ListFindingTriageEvents(ctx context.Context, findingID string, limit int) ([]FindingTriageEvent, error)
	ListScans(ctx context.Context, limit int) ([]ScanRecord, error)
	ListFindings(ctx context.Context, limit int) ([]domain.Finding, error)
	ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error)
	ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error)
	ListRelationships(ctx context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error)
	AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error
	ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error)
	CreateRepoScan(ctx context.Context, repository string, startedAt time.Time) (RepoScanRecord, error)
	CreateQueuedRepoScan(ctx context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error)
	ClaimNextQueuedRepoScan(ctx context.Context) (RepoScanRecord, error)
	CountQueuedRepoScans(ctx context.Context) (int, error)
	CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error)
	RequeueRepoScan(ctx context.Context, repoScanID string) error
	GetRepoScan(ctx context.Context, repoScanID string) (RepoScanRecord, error)
	CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error
	UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error
	ListRepoScans(ctx context.Context, limit int) ([]RepoScanRecord, error)
	ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error)
	Close() error
}
