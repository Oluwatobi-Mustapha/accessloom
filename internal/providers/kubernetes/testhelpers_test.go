package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func loadRawFixture(t *testing.T, kind string, fileName string, sourceID string) providers.RawAsset {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "kubernetes", fileName)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return providers.RawAsset{
		Kind:     kind,
		SourceID: sourceID,
		Payload:  payload,
	}
}
