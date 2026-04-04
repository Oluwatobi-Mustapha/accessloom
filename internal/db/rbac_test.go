package db

import "testing"

func TestNormalizeRBACSubjectType(t *testing.T) {
	got, err := normalizeRBACSubjectType(" OIDC_SUBJECT ")
	if err != nil {
		t.Fatalf("normalize subject type: %v", err)
	}
	if got != RBACSubjectTypeOIDCSubject {
		t.Fatalf("expected %q, got %q", RBACSubjectTypeOIDCSubject, got)
	}

	if _, err := normalizeRBACSubjectType("invalid"); err == nil {
		t.Fatal("expected invalid subject type error")
	}
}

func TestNormalizeRBACPermissionList(t *testing.T) {
	got := normalizeRBACPermissionList([]string{" scans.run ", "findings.read", "FINDINGS.READ", ""})
	if len(got) != 2 {
		t.Fatalf("expected deduped permissions, got %+v", got)
	}
	if got[0] != "findings.read" || got[1] != "scans.run" {
		t.Fatalf("unexpected sorted permissions: %+v", got)
	}
}
