package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"go.uber.org/zap"
)

func TestAPIV1ContractSnapshots(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	router := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	postReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	postW := httptest.NewRecorder()
	router.ServeHTTP(postW, postReq)
	if postW.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for scan trigger, got %d", postW.Code)
	}
	postBody := decodeJSONMap(t, postW.Body.Bytes())
	scanID := normalizeScanTriggerResponse(postBody)
	assertContractSnapshot(t, "api_v1_scan_trigger_response", postBody)
	processed, processErr := svc.ProcessNextQueuedScan(context.Background())
	if processErr != nil {
		t.Fatalf("process queued scan: %v", processErr)
	}
	if !processed {
		t.Fatal("expected queued scan to be processed")
	}

	findingsReq := httptest.NewRequest(http.MethodGet, "/v1/findings?limit=5", nil)
	findingsW := httptest.NewRecorder()
	router.ServeHTTP(findingsW, findingsReq)
	if findingsW.Code != http.StatusOK {
		t.Fatalf("expected 200 for findings list, got %d", findingsW.Code)
	}
	findingsBody := decodeJSONMap(t, findingsW.Body.Bytes())
	normalizeFindingsListResponse(findingsBody, scanID)
	assertContractSnapshot(t, "api_v1_findings_list_response", findingsBody)

	exportsReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1/exports?scan_id="+scanID, nil)
	exportsW := httptest.NewRecorder()
	router.ServeHTTP(exportsW, exportsReq)
	if exportsW.Code != http.StatusOK {
		t.Fatalf("expected 200 for finding exports, got %d", exportsW.Code)
	}
	exportsBody := decodeJSONMap(t, exportsW.Body.Bytes())
	normalizeFindingExportsResponse(exportsBody)
	assertContractSnapshot(t, "api_v1_finding_exports_response", exportsBody)
}

func decodeJSONMap(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

func normalizeScanTriggerResponse(body map[string]any) string {
	scan, _ := body["scan"].(map[string]any)
	scanID, _ := scan["id"].(string)
	scan["id"] = "<scan-id>"
	if _, ok := scan["started_at"]; ok {
		scan["started_at"] = "<timestamp>"
	}
	if _, ok := scan["finished_at"]; ok {
		scan["finished_at"] = "<timestamp>"
	}
	return scanID
}

func normalizeFindingsListResponse(body map[string]any, scanID string) {
	items, _ := body["items"].([]any)
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if itemScanID, ok := item["scan_id"].(string); ok && itemScanID == scanID {
			item["scan_id"] = "<scan-id>"
		}
		if _, ok := item["created_at"]; ok {
			item["created_at"] = "<timestamp>"
		}
	}
}

func normalizeFindingExportsResponse(body map[string]any) {
	ocsf, _ := body["ocsf"].(map[string]any)
	findingInfo, _ := ocsf["finding_info"].(map[string]any)
	if _, ok := findingInfo["created"]; ok {
		findingInfo["created"] = "<timestamp>"
	}
	if _, ok := findingInfo["scan_id"]; ok {
		findingInfo["scan_id"] = "<scan-id>"
	}

	asff, _ := body["asff"].(map[string]any)
	if _, ok := asff["CreatedAt"]; ok {
		asff["CreatedAt"] = "<timestamp>"
	}
	if _, ok := asff["UpdatedAt"]; ok {
		asff["UpdatedAt"] = "<timestamp>"
	}
	productFields, _ := asff["ProductFields"].(map[string]any)
	if _, ok := productFields["ScanID"]; ok {
		productFields["ScanID"] = "<scan-id>"
	}
}

func assertContractSnapshot(t *testing.T, name string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal snapshot %s: %v", name, err)
	}
	data = append(data, '\n')

	path := contractSnapshotPath(t, name)
	if os.Getenv("UPDATE_CONTRACT_SNAPSHOTS") == "1" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write snapshot %s: %v", name, err)
		}
	}

	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot %s: %v", name, err)
	}
	if string(expected) != string(data) {
		t.Fatalf("snapshot mismatch for %s\nexpected:\n%s\nactual:\n%s", name, string(expected), string(data))
	}
}

func contractSnapshotPath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(root, "testdata", "contracts", name+".snapshot.json")
}
