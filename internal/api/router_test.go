package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"go.uber.org/zap"
)

type routerScanner struct{}

func (routerScanner) Run(_ context.Context) (app.ScanResult, error) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	return app.ScanResult{
		Assets: 1,
		Findings: []domain.Finding{{
			ID:           "f1",
			Type:         domain.FindingRiskyTrustPolicy,
			Severity:     domain.SeverityHigh,
			Title:        "Risky trust",
			HumanSummary: "summary",
			CreatedAt:    now,
		}},
		Completed: now,
	}, nil
}

func TestRouterHealthz(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("unexpected status body: %+v", body)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected security header nosniff, got %q", got)
	}
}

func TestRouterRunsScanAndListsData(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc)

	postReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	postW := httptest.NewRecorder()
	r.ServeHTTP(postW, postReq)
	if postW.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", postW.Code)
	}

	findingsReq := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	findingsW := httptest.NewRecorder()
	r.ServeHTTP(findingsW, findingsReq)
	if findingsW.Code != http.StatusOK {
		t.Fatalf("expected findings 200, got %d", findingsW.Code)
	}
	if !json.Valid(findingsW.Body.Bytes()) {
		t.Fatalf("expected valid json findings body: %s", findingsW.Body.String())
	}

	scansReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	scansW := httptest.NewRecorder()
	r.ServeHTTP(scansW, scansReq)
	if scansW.Code != http.StatusOK {
		t.Fatalf("expected scans 200, got %d", scansW.Code)
	}
}

func TestRouterUnavailableWhenServiceMissing(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}
}

func TestRouterScanConflictWhenLocked(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")

	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire("scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()
	svc.Locker = locker

	r := NewRouter(logger, metrics, svc)
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}
}

func TestParseLimit(t *testing.T) {
	if got := parseLimit("", 10, 500); got != 10 {
		t.Fatalf("expected fallback 10, got %d", got)
	}
	if got := parseLimit("invalid", 10, 500); got != 10 {
		t.Fatalf("expected fallback 10, got %d", got)
	}
	if got := parseLimit("1000", 10, 500); got != 500 {
		t.Fatalf("expected clamp 500, got %d", got)
	}
	if got := parseLimit("25", 10, 500); got != 25 {
		t.Fatalf("expected 25, got %d", got)
	}
}
