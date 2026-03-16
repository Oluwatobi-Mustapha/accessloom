package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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

type recordingAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *recordingAuditSink) Write(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (*recordingAuditSink) Close() error { return nil }

func TestRouterHealthz(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{})

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
	r := NewRouter(logger, metrics, svc, RouterOptions{})

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
	r := NewRouter(logger, metrics, nil, RouterOptions{})

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

	r := NewRouter(logger, metrics, svc, RouterOptions{})
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}
}

func TestRouterRequiresAPIKeyForV1(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{APIKeys: []string{"secret-key"}})

	unauthReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	unauthW := httptest.NewRecorder()
	r.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthW.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	authReq.Header.Set("X-API-Key", "secret-key")
	authW := httptest.NewRecorder()
	r.ServeHTTP(authW, authReq)
	if authW.Code != http.StatusOK {
		t.Fatalf("expected 200 with api key, got %d", authW.Code)
	}
}

func TestRouterWriteAuthorization(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"read-key", "write-key"},
		WriteAPIKeys: []string{"write-key"},
	})

	readReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	readReq.Header.Set("X-API-Key", "read-key")
	readW := httptest.NewRecorder()
	r.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("expected read with read-key to pass, got %d", readW.Code)
	}

	writeDeniedReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeDeniedReq.Header.Set("X-API-Key", "read-key")
	writeDeniedW := httptest.NewRecorder()
	r.ServeHTTP(writeDeniedW, writeDeniedReq)
	if writeDeniedW.Code != http.StatusForbidden {
		t.Fatalf("expected write with read-key to be forbidden, got %d", writeDeniedW.Code)
	}

	writeAllowedReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeAllowedReq.Header.Set("X-API-Key", "write-key")
	writeAllowedW := httptest.NewRecorder()
	r.ServeHTTP(writeAllowedW, writeAllowedReq)
	if writeAllowedW.Code != http.StatusAccepted {
		t.Fatalf("expected write with write-key to pass, got %d", writeAllowedW.Code)
	}
}

func TestRouterScopedAuthorizationPrefersScopeMap(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"legacy-key"},
		WriteAPIKeys: []string{"legacy-key"},
		APIKeyScopes: map[string][]string{
			"reader-key": {"read"},
			"writer-key": {"read", scopeWrite},
		},
	})

	legacyReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	legacyReq.Header.Set("X-API-Key", "legacy-key")
	legacyW := httptest.NewRecorder()
	r.ServeHTTP(legacyW, legacyReq)
	if legacyW.Code != http.StatusUnauthorized {
		t.Fatalf("expected legacy key rejected when scoped keys set, got %d", legacyW.Code)
	}

	readReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	readReq.Header.Set("X-API-Key", "reader-key")
	readW := httptest.NewRecorder()
	r.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("expected read with reader-key to pass, got %d", readW.Code)
	}

	readWriteDeniedReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	readWriteDeniedReq.Header.Set("X-API-Key", "reader-key")
	readWriteDeniedW := httptest.NewRecorder()
	r.ServeHTTP(readWriteDeniedW, readWriteDeniedReq)
	if readWriteDeniedW.Code != http.StatusForbidden {
		t.Fatalf("expected writer action to fail with reader-key, got %d", readWriteDeniedW.Code)
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeReq.Header.Set("Authorization", "Bearer writer-key")
	writeW := httptest.NewRecorder()
	r.ServeHTTP(writeW, writeReq)
	if writeW.Code != http.StatusAccepted {
		t.Fatalf("expected write with writer-key to pass, got %d", writeW.Code)
	}
}

func TestRouterRateLimitExceeded(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{RateLimitRPM: 1, RateLimitBurst: 1})

	first := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	first.RemoteAddr = "127.0.0.1:12345"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	second.RemoteAddr = "127.0.0.1:12345"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", w2.Code)
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

func TestRouterEmitsAuditLog(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	entries := observed.FilterMessage("api request").All()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit log entry")
	}
	last := entries[len(entries)-1]
	if got := last.ContextMap()["path"]; got != "/v1/scans" {
		t.Fatalf("expected path /v1/scans, got %v", got)
	}
	if got := last.ContextMap()["method"]; got != "GET" {
		t.Fatalf("expected method GET, got %v", got)
	}
}

func TestRouterWritesAuditSink(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{AuditSink: sink})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	req.Header.Set("User-Agent", "router-test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected sink to capture at least one event")
	}
	event := sink.events[len(sink.events)-1]
	if event.Path != "/v1/scans" || event.Method != http.MethodGet {
		t.Fatalf("unexpected sink event: %+v", event)
	}
	if event.UserAgent != "router-test" {
		t.Fatalf("unexpected user agent in event: %q", event.UserAgent)
	}
}
