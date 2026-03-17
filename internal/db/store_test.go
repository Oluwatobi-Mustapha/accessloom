package db

import "testing"

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
