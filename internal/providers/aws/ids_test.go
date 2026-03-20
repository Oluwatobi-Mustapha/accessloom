package aws

import (
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

func TestRelationshipIDUsesDeterministicSHA256Prefix(t *testing.T) {
	idA := relationshipID(
		domain.RelationshipCanAssume,
		"aws:principal:*",
		"aws:identity:arn:aws:iam::123456789012:role/demo",
	)
	idB := relationshipID(
		domain.RelationshipCanAssume,
		"aws:principal:*",
		"aws:identity:arn:aws:iam::123456789012:role/demo",
	)

	if idA != idB {
		t.Fatalf("expected deterministic relationship IDs, got %q vs %q", idA, idB)
	}
	if !strings.HasPrefix(idA, "aws:rel:") {
		t.Fatalf("unexpected relationship ID prefix: %q", idA)
	}
	hashPart := strings.TrimPrefix(idA, "aws:rel:")
	if len(hashPart) != 32 {
		t.Fatalf("expected 128-bit hex hash suffix (32 chars), got %d in %q", len(hashPart), idA)
	}
}

func TestFindingIDUsesDeterministicSHA256Prefix(t *testing.T) {
	idA := findingID(domain.FindingOverPrivileged, "aws:identity:role/demo", "salt-a")
	idB := findingID(domain.FindingOverPrivileged, "aws:identity:role/demo", "salt-a")
	idC := findingID(domain.FindingOverPrivileged, "aws:identity:role/demo", "salt-b")

	if idA != idB {
		t.Fatalf("expected deterministic finding IDs, got %q vs %q", idA, idB)
	}
	if idA == idC {
		t.Fatalf("expected different finding IDs for different salts, both were %q", idA)
	}
	if !strings.HasPrefix(idA, "aws:finding:") {
		t.Fatalf("unexpected finding ID prefix: %q", idA)
	}
	hashPart := strings.TrimPrefix(idA, "aws:finding:")
	if len(hashPart) != 32 {
		t.Fatalf("expected 128-bit hex hash suffix (32 chars), got %d in %q", len(hashPart), idA)
	}
}
