package domain

import "time"

// Provider identifies the source platform of identity and workload data.
type Provider string

const (
	ProviderAWS        Provider = "aws"
	ProviderKubernetes Provider = "kubernetes"
	ProviderAzure      Provider = "azure"
)

// IdentityType describes a machine identity category.
type IdentityType string

const (
	IdentityTypeRole           IdentityType = "role"
	IdentityTypeUser           IdentityType = "user"
	IdentityTypeServiceAccount IdentityType = "service_account"
	IdentityTypePrincipal      IdentityType = "principal"
)

// RelationshipType captures graph edge semantics used by path and blast radius analysis.
type RelationshipType string

const (
	RelationshipCanAssume      RelationshipType = "can_assume"
	RelationshipAttachedPolicy RelationshipType = "attached_policy"
	RelationshipBoundTo        RelationshipType = "bound_to"
	RelationshipCanAccess      RelationshipType = "can_access"
)

// FindingSeverity aligns risk scoring with operator expectations.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// FindingType keeps rule output strongly typed for filtering and remediation.
type FindingType string

const (
	FindingOverPrivileged   FindingType = "overprivileged_identity"
	FindingEscalationPath   FindingType = "escalation_path"
	FindingStaleIdentity    FindingType = "stale_identity"
	FindingOwnerless        FindingType = "ownerless_identity"
	FindingRiskyTrustPolicy FindingType = "risky_trust_policy"
)

// Identity is a normalized machine identity across providers.
type Identity struct {
	ID         string            `json:"id"`
	Provider   Provider          `json:"provider"`
	Type       IdentityType      `json:"type"`
	Name       string            `json:"name"`
	ARN        string            `json:"arn"`
	OwnerHint  string            `json:"owner_hint"`
	CreatedAt  time.Time         `json:"created_at"`
	LastUsedAt *time.Time        `json:"last_used_at,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	RawRef     string            `json:"raw_ref"`
}

// Workload is a compute entity that can execute with one or more identities.
type Workload struct {
	ID        string   `json:"id"`
	Provider  Provider `json:"provider"`
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	AccountID string   `json:"account_id"`
	Region    string   `json:"region"`
	RawRef    string   `json:"raw_ref"`
}

// Policy stores provider-native policy documents and parsed summaries.
type Policy struct {
	ID         string         `json:"id"`
	Provider   Provider       `json:"provider"`
	Name       string         `json:"name"`
	Document   []byte         `json:"document"`
	Normalized map[string]any `json:"normalized,omitempty"`
	RawRef     string         `json:"raw_ref"`
}

// Relationship models directional edges in the permission graph.
type Relationship struct {
	ID           string           `json:"id"`
	Type         RelationshipType `json:"type"`
	FromNodeID   string           `json:"from_node_id"`
	ToNodeID     string           `json:"to_node_id"`
	EvidenceRef  string           `json:"evidence_ref"`
	DiscoveredAt time.Time        `json:"discovered_at"`
}

// Finding is a typed risk detected by the analysis engine.
type Finding struct {
	ID           string          `json:"id"`
	ScanID       string          `json:"scan_id"`
	Type         FindingType     `json:"type"`
	Severity     FindingSeverity `json:"severity"`
	Title        string          `json:"title"`
	HumanSummary string          `json:"human_summary"`
	Path         []string        `json:"path,omitempty"`
	Evidence     map[string]any  `json:"evidence,omitempty"`
	Remediation  string          `json:"remediation"`
	CreatedAt    time.Time       `json:"created_at"`
}

// OwnershipSignal tracks ownership hints and confidence.
type OwnershipSignal struct {
	ID         string  `json:"id"`
	IdentityID string  `json:"identity_id"`
	Team       string  `json:"team"`
	Repository string  `json:"repository"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
}

// Scan tracks one full ingestion and analysis run.
type Scan struct {
	ID         string     `json:"id"`
	Provider   Provider   `json:"provider"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
}
