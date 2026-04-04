package api

import (
	"errors"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
)

func TestServiceRBACRoleAndBindingLifecycle(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, nil, "aws")
	ctx := defaultScopeContext()

	role, err := svc.UpsertRBACRole(ctx, db.RBACRole{
		Name:        " Viewer ",
		Description: " read only ",
		Permissions: []string{"Scans.Read", "findings.read", "scans.read", "   "},
	})
	if err != nil {
		t.Fatalf("upsert role: %v", err)
	}
	if role.Name != "viewer" {
		t.Fatalf("expected normalized role name, got %q", role.Name)
	}

	roles, err := svc.ListRBACRoles(ctx)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected one role, got %d", len(roles))
	}
	if len(roles[0].Permissions) != 2 {
		t.Fatalf("expected deduped permissions, got %+v", roles[0].Permissions)
	}

	expiresLocal := time.Date(2026, 4, 4, 15, 0, 0, 0, time.FixedZone("WAT", 3600))
	binding, err := svc.UpsertRBACBinding(ctx, db.RBACBinding{
		SubjectType: db.RBACSubjectTypeOIDCSubject,
		SubjectID:   " user-1 ",
		RoleID:      " " + role.ID + " ",
		ExpiresAt:   &expiresLocal,
	})
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if binding.ExpiresAt == nil || binding.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expected UTC expires_at, got %+v", binding.ExpiresAt)
	}

	bindings, err := svc.ListRBACBindings(ctx)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected one binding, got %d", len(bindings))
	}

	if err := svc.DeleteRBACBinding(ctx, " "+binding.ID+" "); err != nil {
		t.Fatalf("delete binding: %v", err)
	}
	if err := svc.DeleteRBACRole(ctx, " "+role.ID+" "); err != nil {
		t.Fatalf("delete role: %v", err)
	}
}

func TestServiceRBACInputValidation(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), nil, "aws")
	ctx := defaultScopeContext()

	if _, err := svc.UpsertRBACRole(ctx, db.RBACRole{Name: "", Permissions: []string{"findings.read"}}); err == nil {
		t.Fatal("expected role name validation error")
	}
	if _, err := svc.UpsertRBACRole(ctx, db.RBACRole{Name: "custom", Permissions: []string{" ", ""}}); err == nil {
		t.Fatal("expected role permissions validation error")
	}
	if _, err := svc.UpsertRBACBinding(ctx, db.RBACBinding{SubjectType: db.RBACSubjectTypeOIDCSubject, RoleID: "role-1"}); err == nil {
		t.Fatal("expected missing subject id error")
	}
	if _, err := svc.UpsertRBACBinding(ctx, db.RBACBinding{SubjectType: db.RBACSubjectTypeOIDCSubject, SubjectID: "user-1"}); err == nil {
		t.Fatal("expected missing role id error")
	}

	if err := svc.DeleteRBACBinding(ctx, " "); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting blank binding id, got %v", err)
	}
	if err := svc.DeleteRBACRole(ctx, " "); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting blank role id, got %v", err)
	}
}

func TestParseOptionalRFC3339(t *testing.T) {
	if got, err := parseOptionalRFC3339("   "); err != nil || got != nil {
		t.Fatalf("expected nil timestamp, got %v err=%v", got, err)
	}

	parsed, err := parseOptionalRFC3339("2026-04-04T21:30:00+01:00")
	if err != nil {
		t.Fatalf("parse rfc3339: %v", err)
	}
	if parsed == nil || parsed.Location() != time.UTC {
		t.Fatalf("expected UTC timestamp, got %+v", parsed)
	}

	if _, err := parseOptionalRFC3339("not-a-timestamp"); err == nil {
		t.Fatal("expected parse error for invalid timestamp")
	}
}

func TestNormalizePermissionList(t *testing.T) {
	got := normalizePermissionList([]string{" findings.read ", "FINDINGS.READ", "scans.run", ""})
	if len(got) != 2 {
		t.Fatalf("expected 2 permissions, got %+v", got)
	}
	if got[0] != "findings.read" || got[1] != "scans.run" {
		t.Fatalf("unexpected normalized permissions: %+v", got)
	}
}
