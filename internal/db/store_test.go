package db

import (
	"testing"
	"time"
)

func TestNormalizeScanEventLevel(t *testing.T) {
	cases := []string{ScanEventLevelDebug, ScanEventLevelInfo, ScanEventLevelWarn, ScanEventLevelError}
	for _, c := range cases {
		got, err := NormalizeScanEventLevel(c)
		if err != nil {
			t.Fatalf("expected valid level %q, got err %v", c, err)
		}
		if got != c {
			t.Fatalf("expected %q, got %q", c, got)
		}
	}
	if _, err := NormalizeScanEventLevel("bogus"); err == nil {
		t.Fatal("expected invalid level error")
	}
}

func TestStoreCloseHelpers(t *testing.T) {
	mem := NewMemoryStore()
	if err := mem.Close(); err != nil {
		t.Fatalf("memory close failed: %v", err)
	}

	postgres := &PostgresStore{}
	if err := postgres.Close(); err != nil {
		t.Fatalf("nil postgres close failed: %v", err)
	}
}

func TestNormalizeAuthzEntityAttributesForWrite(t *testing.T) {
	normalized, err := NormalizeAuthzEntityAttributesForWrite(AuthzEntityAttributes{
		EntityKind:     "RESOURCE",
		EntityType:     "Finding",
		EntityID:       "finding-1",
		OwnerTeam:      "Platform_Sec",
		Environment:    "Prod",
		RiskTier:       "High",
		Classification: "Confidential",
		UpdatedAt:      time.Date(2026, 4, 8, 12, 0, 0, 0, time.FixedZone("WAT", 1*60*60)),
	})
	if err != nil {
		t.Fatalf("normalize entity attributes failed: %v", err)
	}
	if normalized.EntityKind != AuthzEntityKindResource {
		t.Fatalf("expected entity kind %q, got %q", AuthzEntityKindResource, normalized.EntityKind)
	}
	if normalized.OwnerTeam != "platform_sec" {
		t.Fatalf("expected owner team normalized to lower case, got %q", normalized.OwnerTeam)
	}
	if normalized.Environment != AuthzAttributeEnvProd {
		t.Fatalf("expected env %q, got %q", AuthzAttributeEnvProd, normalized.Environment)
	}
	if normalized.UpdatedAt.Location() != time.UTC {
		t.Fatalf("expected UTC updated_at, got %v", normalized.UpdatedAt.Location())
	}

	if _, err := NormalizeAuthzEntityAttributesForWrite(AuthzEntityAttributes{
		EntityKind:  AuthzEntityKindResource,
		EntityType:  "finding",
		EntityID:    "finding-1",
		Environment: "qa",
	}); err == nil {
		t.Fatal("expected invalid env error")
	}

	if _, err := NormalizeAuthzEntityAttributesForWrite(AuthzEntityAttributes{
		EntityKind: AuthzEntityKindSubject,
		EntityType: "user",
		EntityID:   "alice",
		OwnerTeam:  "platform sec",
	}); err == nil {
		t.Fatal("expected invalid owner_team format error")
	}

	implicitTime, err := NormalizeAuthzEntityAttributesForWrite(AuthzEntityAttributes{
		EntityKind: AuthzEntityKindSubject,
		EntityType: "user",
		EntityID:   "alice",
	})
	if err != nil {
		t.Fatalf("expected valid subject attrs with generated updated_at, got %v", err)
	}
	if implicitTime.UpdatedAt.IsZero() {
		t.Fatal("expected non-zero generated updated_at")
	}
}

func TestNormalizeAuthzRelationshipForWrite(t *testing.T) {
	expiresAt := time.Date(2026, 4, 9, 12, 0, 0, 0, time.FixedZone("WAT", 1*60*60))
	normalized, err := NormalizeAuthzRelationshipForWrite(AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "user-1",
		Relation:    "MANAGES",
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
		Source:      "SYNC",
		ExpiresAt:   &expiresAt,
	})
	if err != nil {
		t.Fatalf("normalize relationship failed: %v", err)
	}
	if normalized.Relation != AuthzRelationshipManages {
		t.Fatalf("expected relation %q, got %q", AuthzRelationshipManages, normalized.Relation)
	}
	if normalized.Source != "sync" {
		t.Fatalf("expected source lower-cased, got %q", normalized.Source)
	}
	if normalized.ExpiresAt == nil || normalized.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expected UTC expires_at, got %+v", normalized.ExpiresAt)
	}

	if _, err := NormalizeAuthzRelationshipForWrite(AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "user-1",
		Relation:    "viewer",
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
	}); err == nil {
		t.Fatal("expected invalid relation error")
	}

	defaultSource, err := NormalizeAuthzRelationshipForWrite(AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "user-2",
		Relation:    AuthzRelationshipOwns,
		ObjectType:  "finding",
		ObjectID:    "finding-2",
	})
	if err != nil {
		t.Fatalf("normalize relationship with default source failed: %v", err)
	}
	if defaultSource.Source != "manual" {
		t.Fatalf("expected default source manual, got %q", defaultSource.Source)
	}
}

func TestNormalizeAuthzPolicySetForWrite(t *testing.T) {
	normalized, err := NormalizeAuthzPolicySetForWrite(AuthzPolicySet{
		PolicySetID: " CORE_POLICY ",
		DisplayName: " Core Policy ",
		Description: " baseline policy ",
		CreatedBy:   " owner ",
		CreatedAt:   time.Date(2026, 4, 8, 18, 0, 0, 0, time.FixedZone("WAT", 1*60*60)),
	})
	if err != nil {
		t.Fatalf("normalize policy set: %v", err)
	}
	if normalized.PolicySetID != "core_policy" {
		t.Fatalf("expected normalized policy_set_id, got %q", normalized.PolicySetID)
	}
	if normalized.DisplayName != "Core Policy" {
		t.Fatalf("expected trimmed display name, got %q", normalized.DisplayName)
	}
	if normalized.CreatedAt.Location() != time.UTC || normalized.UpdatedAt.Location() != time.UTC {
		t.Fatalf("expected UTC timestamps, got created=%v updated=%v", normalized.CreatedAt.Location(), normalized.UpdatedAt.Location())
	}
	if normalized.CreatedBy != "owner" {
		t.Fatalf("expected trimmed created_by, got %q", normalized.CreatedBy)
	}

	if _, err := NormalizeAuthzPolicySetForWrite(AuthzPolicySet{
		PolicySetID: "invalid policy",
		DisplayName: "Core",
	}); err == nil {
		t.Fatal("expected invalid policy set id error")
	}
	if _, err := NormalizeAuthzPolicySetForWrite(AuthzPolicySet{
		PolicySetID: "   ",
		DisplayName: "Core",
	}); err == nil {
		t.Fatal("expected missing policy set id error")
	}
}

func TestNormalizeAuthzPolicyVersionForWrite(t *testing.T) {
	normalized, err := NormalizeAuthzPolicyVersionForWrite(AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     1,
		Bundle:      `{"rules":[{"id":"r1","effect":"allow"}]}`,
	})
	if err != nil {
		t.Fatalf("normalize policy version: %v", err)
	}
	if normalized.Checksum == "" {
		t.Fatal("expected computed checksum")
	}
	if normalized.CreatedAt.IsZero() {
		t.Fatal("expected generated created_at")
	}
	withChecksum, err := NormalizeAuthzPolicyVersionForWrite(AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     2,
		Bundle:      `{"rules":[{"id":"r2","effect":"allow"}]}`,
		Checksum:    " ABCDEF ",
	})
	if err != nil {
		t.Fatalf("normalize policy version with provided checksum: %v", err)
	}
	if withChecksum.Checksum != "abcdef" {
		t.Fatalf("expected normalized provided checksum, got %q", withChecksum.Checksum)
	}

	if _, err := NormalizeAuthzPolicyVersionForWrite(AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     1,
		Bundle:      "not-json",
	}); err == nil {
		t.Fatal("expected invalid json bundle error")
	}
	if _, err := NormalizeAuthzPolicyVersionForWrite(AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     0,
		Bundle:      `{"rules":[]}`,
	}); err == nil {
		t.Fatal("expected invalid version error")
	}
}

func TestNormalizeAuthzPolicyRolloutForWrite(t *testing.T) {
	active := 1
	candidate := 2
	normalized, err := NormalizeAuthzPolicyRolloutForWrite(AuthzPolicyRollout{
		PolicySetID:        "core_policy",
		ActiveVersion:      &active,
		CandidateVersion:   &candidate,
		Mode:               "ENFORCE",
		TenantAllowlist:    []string{" tenant-a ", "tenant-a", "tenant-b"},
		WorkspaceAllowlist: []string{"workspace-a", "workspace-a"},
		CanaryPercentage:   25,
		ValidatedVersions:  []int{2, 1, 2},
		UpdatedBy:          " owner ",
	})
	if err != nil {
		t.Fatalf("normalize policy rollout: %v", err)
	}
	if normalized.Mode != AuthzPolicyRolloutModeEnforce {
		t.Fatalf("expected enforce mode, got %q", normalized.Mode)
	}
	if normalized.UpdatedBy != "owner" {
		t.Fatalf("expected trimmed updated_by, got %q", normalized.UpdatedBy)
	}
	if normalized.CanaryPercentage != 25 {
		t.Fatalf("expected canary percentage 25, got %d", normalized.CanaryPercentage)
	}
	if len(normalized.TenantAllowlist) != 2 {
		t.Fatalf("expected normalized tenant allowlist, got %+v", normalized.TenantAllowlist)
	}
	if len(normalized.WorkspaceAllowlist) != 1 || normalized.WorkspaceAllowlist[0] != "workspace-a" {
		t.Fatalf("expected normalized workspace allowlist, got %+v", normalized.WorkspaceAllowlist)
	}
	if len(normalized.ValidatedVersions) != 2 || normalized.ValidatedVersions[0] != 1 || normalized.ValidatedVersions[1] != 2 {
		t.Fatalf("expected sorted validated versions [1 2], got %+v", normalized.ValidatedVersions)
	}

	if _, err := NormalizeAuthzPolicyRolloutForWrite(AuthzPolicyRollout{
		PolicySetID: "core_policy",
		Mode:        "unknown",
	}); err == nil {
		t.Fatal("expected invalid rollout mode error")
	}

	candidateZero := 0
	if _, err := NormalizeAuthzPolicyRolloutForWrite(AuthzPolicyRollout{
		PolicySetID:      "core_policy",
		CandidateVersion: &candidateZero,
		Mode:             AuthzPolicyRolloutModeShadow,
	}); err == nil {
		t.Fatal("expected invalid candidate version error")
	}

	defaulted, err := NormalizeAuthzPolicyRolloutForWrite(AuthzPolicyRollout{
		PolicySetID: "core_policy",
	})
	if err != nil {
		t.Fatalf("normalize policy rollout with default mode: %v", err)
	}
	if defaulted.Mode != AuthzPolicyRolloutModeDisabled {
		t.Fatalf("expected disabled default rollout mode, got %q", defaulted.Mode)
	}
	if defaulted.CanaryPercentage != 100 {
		t.Fatalf("expected default canary percentage 100, got %d", defaulted.CanaryPercentage)
	}

	if _, err := NormalizeAuthzPolicyRolloutForWrite(AuthzPolicyRollout{
		PolicySetID:      "core_policy",
		Mode:             AuthzPolicyRolloutModeEnforce,
		ActiveVersion:    &active,
		CandidateVersion: &candidate,
		ValidatedVersions: []int{
			active,
		},
	}); err == nil {
		t.Fatal("expected enforce rollout missing validated candidate to fail")
	}

	invalidValidatedVersion := 0
	if _, err := NormalizeAuthzPolicyRolloutForWrite(AuthzPolicyRollout{
		PolicySetID:       "core_policy",
		Mode:              AuthzPolicyRolloutModeShadow,
		ValidatedVersions: []int{invalidValidatedVersion},
	}); err == nil {
		t.Fatal("expected invalid validated version to fail")
	}

	if _, err := NormalizeAuthzPolicyRolloutForWrite(AuthzPolicyRollout{
		PolicySetID:      "core_policy",
		Mode:             AuthzPolicyRolloutModeShadow,
		CanaryPercentage: 101,
	}); err == nil {
		t.Fatal("expected invalid canary percentage to fail")
	}
}

func TestNormalizeAuthzPolicyEventForWrite(t *testing.T) {
	fromVersion := 1
	toVersion := 2
	normalized, err := NormalizeAuthzPolicyEventForWrite(AuthzPolicyEvent{
		PolicySetID: "core_policy",
		EventType:   "Promote",
		FromVersion: &fromVersion,
		ToVersion:   &toVersion,
		Actor:       " owner ",
		Message:     " promoted ",
	})
	if err != nil {
		t.Fatalf("normalize policy event: %v", err)
	}
	if normalized.EventType != "promote" {
		t.Fatalf("expected lower-cased event type, got %q", normalized.EventType)
	}
	if normalized.Actor != "owner" || normalized.Message != "promoted" {
		t.Fatalf("expected trimmed actor/message, got actor=%q message=%q", normalized.Actor, normalized.Message)
	}
	if normalized.CreatedAt.IsZero() {
		t.Fatal("expected generated created_at")
	}

	invalid := 0
	if _, err := NormalizeAuthzPolicyEventForWrite(AuthzPolicyEvent{
		PolicySetID: "core_policy",
		EventType:   "promote",
		ToVersion:   &invalid,
	}); err == nil {
		t.Fatal("expected invalid to_version error")
	}
	if _, err := NormalizeAuthzPolicyEventForWrite(AuthzPolicyEvent{
		PolicySetID: "core_policy",
		EventType:   "",
	}); err == nil {
		t.Fatal("expected missing event type error")
	}
}
