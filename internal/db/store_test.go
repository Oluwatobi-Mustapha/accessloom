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
