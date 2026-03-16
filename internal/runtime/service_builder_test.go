package runtime

import (
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestBuildScanServiceMemoryStore(t *testing.T) {
	cfg := config.Config{
		Provider:       "aws",
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
		ScanInterval:   5 * time.Minute,
	}

	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc == nil || closeFn == nil {
		t.Fatal("expected non-nil service and close function")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestNewStoreMemoryAndInvalidPostgres(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("expected memory store, got err: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close memory store: %v", err)
	}

	_, err = NewStore("postgres://user:pass@127.0.0.1:1/identrail?sslmode=disable&connect_timeout=1")
	if err == nil {
		t.Fatal("expected postgres init error")
	}
}
