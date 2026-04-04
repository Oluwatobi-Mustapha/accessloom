package review

import (
	"path/filepath"
	"regexp"
	"testing"
)

func TestReadFileAndHelpers(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join("nested", "file.txt")
	full := filepath.Join(root, rel)
	if err := writeFile(full, "line1\nsecret=abc\nline3\n"); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	content, err := readFile(root, rel)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if content == "" {
		t.Fatal("expected non-empty content")
	}

	if got := lineOfSubstring(content, "secret=abc"); got != 2 {
		t.Fatalf("unexpected substring line: %d", got)
	}
	if got := lineOfSubstring(content, "missing"); got != 1 {
		t.Fatalf("unexpected fallback line: %d", got)
	}
	if got := lineOfSubstring(content, ""); got != 1 {
		t.Fatalf("unexpected empty needle line: %d", got)
	}

	re := regexp.MustCompile(`secret=`)
	if got := lineOfRegex(content, re); got != 2 {
		t.Fatalf("unexpected regex line: %d", got)
	}
}

func TestHeadingLabelAndSlugHelpers(t *testing.T) {
	if !hasHeading("### Summary\nok", "summary") {
		t.Fatal("expected heading match")
	}
	if hasHeading("### Scope\nok", "summary") {
		t.Fatal("did not expect heading match")
	}
	if !hasLabel([]string{"Kind/Bug"}, "kind/bug") {
		t.Fatal("expected case-insensitive label match")
	}
	if hasLabel([]string{"kind/enhancement"}, "kind/bug") {
		t.Fatal("did not expect label match")
	}
	if got := slugToken("User and operator impact"); got != "user-and-operator-impact" {
		t.Fatalf("unexpected slug token: %q", got)
	}
	if got := slugToken("A/B_C"); got != "a-b-c" {
		t.Fatalf("unexpected slash/underscore normalization: %q", got)
	}
}
