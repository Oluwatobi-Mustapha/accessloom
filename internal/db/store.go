package db

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// ErrNotFound indicates the requested record does not exist.
var ErrNotFound = errors.New("record not found")

// ErrScopeRequired indicates tenant/workspace scope must be provided in context.
var ErrScopeRequired = errors.New("scope is required")

var authzOwnerTeamPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

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

	AuthzEntityKindSubject  = "subject"
	AuthzEntityKindResource = "resource"

	AuthzAttributeEnvProd    = "prod"
	AuthzAttributeEnvStaging = "staging"
	AuthzAttributeEnvDev     = "dev"
	AuthzAttributeEnvTest    = "test"
	AuthzAttributeEnvSandbox = "sandbox"

	AuthzAttributeRiskTierLow      = "low"
	AuthzAttributeRiskTierMedium   = "medium"
	AuthzAttributeRiskTierHigh     = "high"
	AuthzAttributeRiskTierCritical = "critical"

	AuthzAttributeClassificationPublic       = "public"
	AuthzAttributeClassificationInternal     = "internal"
	AuthzAttributeClassificationConfidential = "confidential"
	AuthzAttributeClassificationRestricted   = "restricted"

	AuthzRelationshipOwns           = "owns"
	AuthzRelationshipManages        = "manages"
	AuthzRelationshipDelegatedAdmin = "delegated_admin"
	AuthzRelationshipMemberOf       = "member_of"
)

var validAuthzEntityKinds = map[string]struct{}{
	AuthzEntityKindSubject:  {},
	AuthzEntityKindResource: {},
}

var validAuthzEnvironments = map[string]struct{}{
	AuthzAttributeEnvProd:    {},
	AuthzAttributeEnvStaging: {},
	AuthzAttributeEnvDev:     {},
	AuthzAttributeEnvTest:    {},
	AuthzAttributeEnvSandbox: {},
}

var validAuthzRiskTiers = map[string]struct{}{
	AuthzAttributeRiskTierLow:      {},
	AuthzAttributeRiskTierMedium:   {},
	AuthzAttributeRiskTierHigh:     {},
	AuthzAttributeRiskTierCritical: {},
}

var validAuthzClassifications = map[string]struct{}{
	AuthzAttributeClassificationPublic:       {},
	AuthzAttributeClassificationInternal:     {},
	AuthzAttributeClassificationConfidential: {},
	AuthzAttributeClassificationRestricted:   {},
}

var validAuthzRelationships = map[string]struct{}{
	AuthzRelationshipOwns:           {},
	AuthzRelationshipManages:        {},
	AuthzRelationshipDelegatedAdmin: {},
	AuthzRelationshipMemberOf:       {},
}

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

// AuthzEntityAttributes stores trusted policy attributes for one subject or resource.
type AuthzEntityAttributes struct {
	TenantID       string    `json:"-"`
	WorkspaceID    string    `json:"-"`
	EntityKind     string    `json:"entity_kind"`
	EntityType     string    `json:"entity_type"`
	EntityID       string    `json:"entity_id"`
	OwnerTeam      string    `json:"owner_team,omitempty"`
	Environment    string    `json:"env,omitempty"`
	RiskTier       string    `json:"risk_tier,omitempty"`
	Classification string    `json:"classification,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AuthzRelationship stores one directional relation tuple used by ReBAC checks.
type AuthzRelationship struct {
	TenantID    string     `json:"-"`
	WorkspaceID string     `json:"-"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	Relation    string     `json:"relation"`
	ObjectType  string     `json:"object_type"`
	ObjectID    string     `json:"object_id"`
	Source      string     `json:"source,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// AuthzRelationshipFilter controls scoped ReBAC tuple listing.
type AuthzRelationshipFilter struct {
	SubjectType    string
	SubjectID      string
	Relation       string
	ObjectType     string
	ObjectID       string
	IncludeExpired bool
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

// NormalizeAuthzEntityAttributesForWrite validates and canonicalizes trusted authz attributes.
func NormalizeAuthzEntityAttributesForWrite(attrs AuthzEntityAttributes) (AuthzEntityAttributes, error) {
	normalized := attrs
	normalized.EntityKind = strings.ToLower(strings.TrimSpace(attrs.EntityKind))
	if _, ok := validAuthzEntityKinds[normalized.EntityKind]; !ok {
		return AuthzEntityAttributes{}, fmt.Errorf("invalid authz entity kind")
	}
	normalized.EntityType = strings.ToLower(strings.TrimSpace(attrs.EntityType))
	if normalized.EntityType == "" {
		return AuthzEntityAttributes{}, fmt.Errorf("entity type is required")
	}
	normalized.EntityID = strings.TrimSpace(attrs.EntityID)
	if normalized.EntityID == "" {
		return AuthzEntityAttributes{}, fmt.Errorf("entity id is required")
	}
	normalized.OwnerTeam = strings.ToLower(strings.TrimSpace(attrs.OwnerTeam))
	if normalized.OwnerTeam != "" && !authzOwnerTeamPattern.MatchString(normalized.OwnerTeam) {
		return AuthzEntityAttributes{}, fmt.Errorf("invalid owner_team format")
	}
	normalized.Environment = strings.ToLower(strings.TrimSpace(attrs.Environment))
	if normalized.Environment != "" {
		if _, ok := validAuthzEnvironments[normalized.Environment]; !ok {
			return AuthzEntityAttributes{}, fmt.Errorf("invalid env value")
		}
	}
	normalized.RiskTier = strings.ToLower(strings.TrimSpace(attrs.RiskTier))
	if normalized.RiskTier != "" {
		if _, ok := validAuthzRiskTiers[normalized.RiskTier]; !ok {
			return AuthzEntityAttributes{}, fmt.Errorf("invalid risk_tier value")
		}
	}
	normalized.Classification = strings.ToLower(strings.TrimSpace(attrs.Classification))
	if normalized.Classification != "" {
		if _, ok := validAuthzClassifications[normalized.Classification]; !ok {
			return AuthzEntityAttributes{}, fmt.Errorf("invalid classification value")
		}
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = time.Now().UTC()
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

// NormalizeAuthzRelationshipForWrite validates and canonicalizes relationship tuples.
func NormalizeAuthzRelationshipForWrite(relationship AuthzRelationship) (AuthzRelationship, error) {
	normalized := relationship
	normalized.SubjectType = strings.ToLower(strings.TrimSpace(relationship.SubjectType))
	if normalized.SubjectType == "" {
		return AuthzRelationship{}, fmt.Errorf("subject type is required")
	}
	normalized.SubjectID = strings.TrimSpace(relationship.SubjectID)
	if normalized.SubjectID == "" {
		return AuthzRelationship{}, fmt.Errorf("subject id is required")
	}
	normalized.Relation = strings.ToLower(strings.TrimSpace(relationship.Relation))
	if _, ok := validAuthzRelationships[normalized.Relation]; !ok {
		return AuthzRelationship{}, fmt.Errorf("invalid relation value")
	}
	normalized.ObjectType = strings.ToLower(strings.TrimSpace(relationship.ObjectType))
	if normalized.ObjectType == "" {
		return AuthzRelationship{}, fmt.Errorf("object type is required")
	}
	normalized.ObjectID = strings.TrimSpace(relationship.ObjectID)
	if normalized.ObjectID == "" {
		return AuthzRelationship{}, fmt.Errorf("object id is required")
	}
	normalized.Source = strings.ToLower(strings.TrimSpace(relationship.Source))
	if normalized.Source == "" {
		normalized.Source = "manual"
	}
	if normalized.ExpiresAt != nil {
		utc := normalized.ExpiresAt.UTC()
		normalized.ExpiresAt = &utc
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
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
	UpsertAuthzEntityAttributes(ctx context.Context, attributes AuthzEntityAttributes) error
	GetAuthzEntityAttributes(ctx context.Context, entityKind string, entityType string, entityID string) (AuthzEntityAttributes, error)
	UpsertAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error
	DeleteAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error
	ListAuthzRelationships(ctx context.Context, filter AuthzRelationshipFilter, limit int) ([]AuthzRelationship, error)
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
