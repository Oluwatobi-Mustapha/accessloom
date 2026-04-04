package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/repoexposure"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"github.com/gin-gonic/gin"
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

type fakeTokenVerifier struct {
	tokens map[string]VerifiedToken
}

func (v fakeTokenVerifier) VerifyToken(_ context.Context, rawToken string) (VerifiedToken, error) {
	token, ok := v.tokens[rawToken]
	if !ok {
		return VerifiedToken{}, errors.New("invalid token")
	}
	return token, nil
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

func TestRouterCORSDisabledByDefault(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://app.identrail.io")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no cors allow origin header, got %q", got)
	}
}

func TestRouterCORSAllowsConfiguredOrigin(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		CORSAllowedOrigins: []string{"https://app.identrail.io"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://app.identrail.io")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.identrail.io" {
		t.Fatalf("expected cors allow origin header, got %q", got)
	}
	if !varyHeaderContains(w.Header().Get("Vary"), "Origin") {
		t.Fatalf("expected Vary header to include Origin, got %q", w.Header().Get("Vary"))
	}
}

func TestRouterCORSPreflightBypassesAuth(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys:            []string{"reader-key"},
		WriteAPIKeys:       []string{"reader-key"},
		CORSAllowedOrigins: []string{"https://app.identrail.io"},
	})

	req := httptest.NewRequest(http.MethodOptions, "/v1/findings", nil)
	req.Header.Set("Origin", "https://app.identrail.io")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	req.Header.Set("Access-Control-Request-Headers", "Authorization,X-API-Key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.identrail.io" {
		t.Fatalf("expected cors allow origin header, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodGet) {
		t.Fatalf("expected allow methods header to include GET, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodPatch) {
		t.Fatalf("expected allow methods header to include PATCH, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(strings.ToLower(got), "x-api-key") {
		t.Fatalf("expected allow headers to include x-api-key, got %q", got)
	}
}

func TestRouterCORSSkipsUnlistedOrigin(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		CORSAllowedOrigins: []string{"https://app.identrail.io"},
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no cors allow origin for unlisted origin, got %q", got)
	}
}

func TestRouterIgnoresForwardedIPWhenNoTrustedProxies(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink:      sink,
		RateLimitRPM:   10000,
		RateLimitBurst: 1000,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	req.RemoteAddr = "10.1.1.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	last := sink.events[len(sink.events)-1]
	if last.ClientIP != "10.1.1.1" {
		t.Fatalf("expected remote ip to be used, got %q", last.ClientIP)
	}
}

func TestRouterUsesForwardedIPWhenTrustedProxyConfigured(t *testing.T) {
	logger := zap.NewNop()
	metrics := telemetry.NewMetrics()
	sink := &recordingAuditSink{}
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink:      sink,
		RateLimitRPM:   10000,
		RateLimitBurst: 1000,
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/findings", nil)
	req.RemoteAddr = "10.1.1.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	last := sink.events[len(sink.events)-1]
	if last.ClientIP != "203.0.113.10" {
		t.Fatalf("expected forwarded ip to be used, got %q", last.ClientIP)
	}
}

func TestRouterRunsScanAndListsData(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: historyLimit,
				FilesScanned:   2,
				Findings: []domain.Finding{
					{ID: "repo-f1", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh},
				},
			},
		}
	}
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	postReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	postW := httptest.NewRecorder()
	r.ServeHTTP(postW, postReq)
	if postW.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", postW.Code)
	}
	var postBody struct {
		Scan db.ScanRecord `json:"scan"`
	}
	if err := json.Unmarshal(postW.Body.Bytes(), &postBody); err != nil {
		t.Fatalf("decode post body: %v", err)
	}
	if postBody.Scan.ID == "" {
		t.Fatal("expected scan id in post response")
	}
	firstScanID := postBody.Scan.ID

	postReq2 := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	postW2 := httptest.NewRecorder()
	r.ServeHTTP(postW2, postReq2)
	if postW2.Code != http.StatusAccepted {
		t.Fatalf("expected second scan status 202, got %d", postW2.Code)
	}
	var postBody2 struct {
		Scan db.ScanRecord `json:"scan"`
	}
	if err := json.Unmarshal(postW2.Body.Bytes(), &postBody2); err != nil {
		t.Fatalf("decode second post body: %v", err)
	}
	if postBody2.Scan.ID == "" {
		t.Fatal("expected second scan id in post response")
	}
	for i := 0; i < 2; i++ {
		processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
		if err != nil {
			t.Fatalf("process queued scan: %v", err)
		}
		if !processed {
			t.Fatalf("expected queued scan %d to be processed", i+1)
		}
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

	filteredFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/findings?severity=high&type=risky_trust_policy", nil)
	filteredFindingsW := httptest.NewRecorder()
	r.ServeHTTP(filteredFindingsW, filteredFindingsReq)
	if filteredFindingsW.Code != http.StatusOK {
		t.Fatalf("expected filtered findings 200, got %d", filteredFindingsW.Code)
	}

	findingReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1", nil)
	findingW := httptest.NewRecorder()
	r.ServeHTTP(findingW, findingReq)
	if findingW.Code != http.StatusOK {
		t.Fatalf("expected finding by id 200, got %d", findingW.Code)
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1/exports", nil)
	exportW := httptest.NewRecorder()
	r.ServeHTTP(exportW, exportReq)
	if exportW.Code != http.StatusOK {
		t.Fatalf("expected finding exports 200, got %d", exportW.Code)
	}
	var exportBody struct {
		OCSF map[string]any `json:"ocsf"`
		ASFF map[string]any `json:"asff"`
	}
	if err := json.Unmarshal(exportW.Body.Bytes(), &exportBody); err != nil {
		t.Fatalf("decode export body: %v", err)
	}
	findingInfo, ok := exportBody.OCSF["finding_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected finding_info object in OCSF payload, got %+v", exportBody.OCSF)
	}
	if findingInfo["uid"] != "f1" {
		t.Fatalf("expected ocsf payload, got %+v", exportBody.OCSF)
	}
	if exportBody.ASFF["SchemaVersion"] != "2018-10-08" {
		t.Fatalf("expected ASFF schema version, got %+v", exportBody.ASFF)
	}

	scansReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	scansW := httptest.NewRecorder()
	r.ServeHTTP(scansW, scansReq)
	if scansW.Code != http.StatusOK {
		t.Fatalf("expected scans 200, got %d", scansW.Code)
	}

	summaryReq := httptest.NewRequest(http.MethodGet, "/v1/findings/summary", nil)
	summaryW := httptest.NewRecorder()
	r.ServeHTTP(summaryW, summaryReq)
	if summaryW.Code != http.StatusOK {
		t.Fatalf("expected summary 200, got %d", summaryW.Code)
	}

	trendsReq := httptest.NewRequest(http.MethodGet, "/v1/findings/trends", nil)
	trendsW := httptest.NewRecorder()
	r.ServeHTTP(trendsW, trendsReq)
	if trendsW.Code != http.StatusOK {
		t.Fatalf("expected trends 200, got %d", trendsW.Code)
	}

	trendsFilteredReq := httptest.NewRequest(http.MethodGet, "/v1/findings/trends?severity=high&type=risky_trust_policy", nil)
	trendsFilteredW := httptest.NewRecorder()
	r.ServeHTTP(trendsFilteredW, trendsFilteredReq)
	if trendsFilteredW.Code != http.StatusOK {
		t.Fatalf("expected filtered trends 200, got %d", trendsFilteredW.Code)
	}

	identitiesReq := httptest.NewRequest(http.MethodGet, "/v1/identities", nil)
	identitiesW := httptest.NewRecorder()
	r.ServeHTTP(identitiesW, identitiesReq)
	if identitiesW.Code != http.StatusOK {
		t.Fatalf("expected identities 200, got %d", identitiesW.Code)
	}

	relationshipsReq := httptest.NewRequest(http.MethodGet, "/v1/relationships", nil)
	relationshipsW := httptest.NewRecorder()
	r.ServeHTTP(relationshipsW, relationshipsReq)
	if relationshipsW.Code != http.StatusOK {
		t.Fatalf("expected relationships 200, got %d", relationshipsW.Code)
	}

	ownershipReq := httptest.NewRequest(http.MethodGet, "/v1/ownership/signals", nil)
	ownershipW := httptest.NewRecorder()
	r.ServeHTTP(ownershipW, ownershipReq)
	if ownershipW.Code != http.StatusOK {
		t.Fatalf("expected ownership signals 200, got %d", ownershipW.Code)
	}

	diffReq := httptest.NewRequest(
		http.MethodGet,
		"/v1/scans/"+postBody2.Scan.ID+"/diff?previous_scan_id="+firstScanID,
		nil,
	)
	diffW := httptest.NewRecorder()
	r.ServeHTTP(diffW, diffReq)
	if diffW.Code != http.StatusOK {
		t.Fatalf("expected diff 200, got %d", diffW.Code)
	}

	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/scans/"+postBody.Scan.ID+"/events", nil)
	eventsW := httptest.NewRecorder()
	r.ServeHTTP(eventsW, eventsReq)
	if eventsW.Code != http.StatusOK {
		t.Fatalf("expected events 200, got %d", eventsW.Code)
	}

	eventsFilteredReq := httptest.NewRequest(http.MethodGet, "/v1/scans/"+postBody.Scan.ID+"/events?level=info", nil)
	eventsFilteredW := httptest.NewRecorder()
	r.ServeHTTP(eventsFilteredW, eventsFilteredReq)
	if eventsFilteredW.Code != http.StatusOK {
		t.Fatalf("expected filtered events 200, got %d", eventsFilteredW.Code)
	}

	repoBody := bytes.NewBufferString(`{"repository":"owner/repo","history_limit":50,"max_findings":20}`)
	repoReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", repoBody)
	repoReq.Header.Set("Content-Type", "application/json")
	repoW := httptest.NewRecorder()
	r.ServeHTTP(repoW, repoReq)
	if repoW.Code != http.StatusAccepted {
		t.Fatalf("expected repo scan 202, got %d", repoW.Code)
	}
	processedRepo, processRepoErr := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if processRepoErr != nil {
		t.Fatalf("process queued repo scan: %v", processRepoErr)
	}
	if !processedRepo {
		t.Fatal("expected queued repo scan to be processed")
	}

	repoScansReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans", nil)
	repoScansW := httptest.NewRecorder()
	r.ServeHTTP(repoScansW, repoScansReq)
	if repoScansW.Code != http.StatusOK {
		t.Fatalf("expected repo scans 200, got %d", repoScansW.Code)
	}
	var repoScansBody struct {
		Items []db.RepoScanRecord `json:"items"`
	}
	if err := json.Unmarshal(repoScansW.Body.Bytes(), &repoScansBody); err != nil {
		t.Fatalf("decode repo scans body: %v", err)
	}
	if len(repoScansBody.Items) == 0 {
		t.Fatal("expected repo scan items")
	}

	repoScanID := repoScansBody.Items[0].ID
	repoScanReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans/"+repoScanID, nil)
	repoScanW := httptest.NewRecorder()
	r.ServeHTTP(repoScanW, repoScanReq)
	if repoScanW.Code != http.StatusOK {
		t.Fatalf("expected repo scan detail 200, got %d", repoScanW.Code)
	}

	repoFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/repo-findings?repo_scan_id="+repoScanID, nil)
	repoFindingsW := httptest.NewRecorder()
	r.ServeHTTP(repoFindingsW, repoFindingsReq)
	if repoFindingsW.Code != http.StatusOK {
		t.Fatalf("expected repo findings 200, got %d", repoFindingsW.Code)
	}

	scansPageOneReq := httptest.NewRequest(http.MethodGet, "/v1/scans?limit=1", nil)
	scansPageOneW := httptest.NewRecorder()
	r.ServeHTTP(scansPageOneW, scansPageOneReq)
	if scansPageOneW.Code != http.StatusOK {
		t.Fatalf("expected scans page one 200, got %d", scansPageOneW.Code)
	}
	var scansPageOne struct {
		Items      []db.ScanRecord `json:"items"`
		NextCursor string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(scansPageOneW.Body.Bytes(), &scansPageOne); err != nil {
		t.Fatalf("decode scans page one: %v", err)
	}
	if len(scansPageOne.Items) != 1 || scansPageOne.NextCursor == "" {
		t.Fatalf("expected one scan and next cursor, got %+v", scansPageOne)
	}

	scansPageTwoReq := httptest.NewRequest(http.MethodGet, "/v1/scans?limit=1&cursor="+scansPageOne.NextCursor, nil)
	scansPageTwoW := httptest.NewRecorder()
	r.ServeHTTP(scansPageTwoW, scansPageTwoReq)
	if scansPageTwoW.Code != http.StatusOK {
		t.Fatalf("expected scans page two 200, got %d", scansPageTwoW.Code)
	}
	var scansPageTwo struct {
		Items []db.ScanRecord `json:"items"`
	}
	if err := json.Unmarshal(scansPageTwoW.Body.Bytes(), &scansPageTwo); err != nil {
		t.Fatalf("decode scans page two: %v", err)
	}
	if len(scansPageTwo.Items) != 1 {
		t.Fatalf("expected one scan on page two, got %+v", scansPageTwo)
	}
	if scansPageOne.Items[0].ID == scansPageTwo.Items[0].ID {
		t.Fatalf("expected different scan records across pages, got %q", scansPageTwo.Items[0].ID)
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

	summaryReq := httptest.NewRequest(http.MethodGet, "/v1/findings/summary", nil)
	summaryW := httptest.NewRecorder()
	r.ServeHTTP(summaryW, summaryReq)
	if summaryW.Code != http.StatusOK {
		t.Fatalf("expected summary 200 without service, got %d", summaryW.Code)
	}

	findingReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1", nil)
	findingW := httptest.NewRecorder()
	r.ServeHTTP(findingW, findingReq)
	if findingW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected finding-by-id 503 without service, got %d", findingW.Code)
	}

	exportsReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1/exports", nil)
	exportsW := httptest.NewRecorder()
	r.ServeHTTP(exportsW, exportsReq)
	if exportsW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected finding exports 503 without service, got %d", exportsW.Code)
	}

	identityReq := httptest.NewRequest(http.MethodGet, "/v1/identities", nil)
	identityW := httptest.NewRecorder()
	r.ServeHTTP(identityW, identityReq)
	if identityW.Code != http.StatusOK {
		t.Fatalf("expected identities 200 without service, got %d", identityW.Code)
	}

	ownershipReq := httptest.NewRequest(http.MethodGet, "/v1/ownership/signals", nil)
	ownershipW := httptest.NewRecorder()
	r.ServeHTTP(ownershipW, ownershipReq)
	if ownershipW.Code != http.StatusOK {
		t.Fatalf("expected ownership signals 200 without service, got %d", ownershipW.Code)
	}

	repoReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	repoReq.Header.Set("Content-Type", "application/json")
	repoW := httptest.NewRecorder()
	r.ServeHTTP(repoW, repoReq)
	if repoW.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected repo scan 503 without service, got %d", repoW.Code)
	}

	repoScansReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans", nil)
	repoScansW := httptest.NewRecorder()
	r.ServeHTTP(repoScansW, repoScansReq)
	if repoScansW.Code != http.StatusOK {
		t.Fatalf("expected repo scans 200 without service, got %d", repoScansW.Code)
	}

	repoFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/repo-findings", nil)
	repoFindingsW := httptest.NewRecorder()
	r.ServeHTTP(repoFindingsW, repoFindingsReq)
	if repoFindingsW.Code != http.StatusOK {
		t.Fatalf("expected repo findings 200 without service, got %d", repoFindingsW.Code)
	}
}

func TestRouterScanEnqueueSucceedsWhenExecutionLockIsHeld(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")

	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire("identrail:scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()
	svc.Locker = locker

	r := NewRouter(logger, metrics, svc, RouterOptions{})
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", w.Code)
	}
}

func TestRouterRepoScanEnqueueSucceedsWhenExecutionLockIsHeld(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire("identrail:repo-scan:owner/repo")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()
	svc.Locker = locker

	r := NewRouter(logger, metrics, svc, RouterOptions{})
	req := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", w.Code)
	}
}

func TestRouterScanQueueBackpressure(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.ScanQueueMaxPending = 1
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	firstW := httptest.NewRecorder()
	r.ServeHTTP(firstW, firstReq)
	if firstW.Code != http.StatusAccepted {
		t.Fatalf("expected first enqueue 202, got %d", firstW.Code)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	secondW := httptest.NewRecorder()
	r.ServeHTTP(secondW, secondReq)
	if secondW.Code != http.StatusTooManyRequests {
		t.Fatalf("expected queue backpressure 429, got %d", secondW.Code)
	}
}

func TestRouterRepoScanQueueBackpressureAndDuplicateGuard(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 1
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	firstReq.Header.Set("Content-Type", "application/json")
	firstW := httptest.NewRecorder()
	r.ServeHTTP(firstW, firstReq)
	if firstW.Code != http.StatusAccepted {
		t.Fatalf("expected first repo enqueue 202, got %d", firstW.Code)
	}

	dupReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/repo"}`))
	dupReq.Header.Set("Content-Type", "application/json")
	dupW := httptest.NewRecorder()
	r.ServeHTTP(dupW, dupReq)
	if dupW.Code != http.StatusConflict {
		t.Fatalf("expected duplicate target conflict 409, got %d", dupW.Code)
	}

	otherReq := httptest.NewRequest(http.MethodPost, "/v1/repo-scans", bytes.NewBufferString(`{"repository":"owner/another"}`))
	otherReq.Header.Set("Content-Type", "application/json")
	otherW := httptest.NewRecorder()
	r.ServeHTTP(otherW, otherReq)
	if otherW.Code != http.StatusTooManyRequests {
		t.Fatalf("expected repo queue backpressure 429, got %d", otherW.Code)
	}
}

func TestRouterSupportsFindingsSortParameters(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)

	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f-critical", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, Title: "critical", CreatedAt: now},
		{ID: "f-info", Severity: domain.SeverityInfo, Type: domain.FindingOwnerless, Title: "info", CreatedAt: now},
		{ID: "f-high", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "high", CreatedAt: now},
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/v1/findings?scan_id="+scan.ID+"&sort_by=severity&sort_order=asc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body struct {
		Items []domain.Finding `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Items) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(body.Items))
	}
	if body.Items[0].ID != "f-info" || body.Items[2].ID != "f-critical" {
		t.Fatalf("unexpected sort order by severity asc: %+v", body.Items)
	}
}

func TestRouterSupportsScansSortParameters(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.CompleteScan(defaultScopeContext(), scanA.ID, "completed", now.Add(2*time.Minute), 2, 7, ""); err != nil {
		t.Fatalf("complete scan A: %v", err)
	}
	if err := store.CompleteScan(defaultScopeContext(), scanB.ID, "completed", now.Add(3*time.Minute), 2, 1, ""); err != nil {
		t.Fatalf("complete scan B: %v", err)
	}

	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{RateLimitRPM: 10000, RateLimitBurst: 1000})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans?sort_by=finding_count&sort_order=asc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body struct {
		Items []db.ScanRecord `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(body.Items))
	}
	if body.Items[0].FindingCount != 1 || body.Items[1].FindingCount != 7 {
		t.Fatalf("unexpected scan sort order: %+v", body.Items)
	}
}

func TestSortHelpersFallbackAndLevels(t *testing.T) {
	sortBy, desc := parseSortParams(" ", "invalid", "created_at")
	if sortBy != "created_at" || !desc {
		t.Fatalf("expected fallback sort defaults, got sort_by=%q desc=%t", sortBy, desc)
	}

	if got := scanEventLevelRank("warn"); got <= scanEventLevelRank("info") {
		t.Fatalf("expected warn rank greater than info, got warn=%d info=%d", got, scanEventLevelRank("info"))
	}
}

func TestSortHelpersCoverageForAllCollections(t *testing.T) {
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	findings := []domain.Finding{
		{ID: "f1", Severity: domain.SeverityLow, Type: domain.FindingOwnerless, Title: "b", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "f2", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, Title: "a", CreatedAt: now.Add(-1 * time.Minute)},
	}
	sortFindings(findings, "title", false)
	if findings[0].Title != "a" {
		t.Fatalf("expected title asc sort, got %+v", findings)
	}
	sortFindings(findings, "severity", true)
	if findings[0].Severity != domain.SeverityCritical {
		t.Fatalf("expected severity desc sort, got %+v", findings)
	}

	scans := []db.ScanRecord{
		{ID: "s1", Status: "completed", AssetCount: 2, FindingCount: 8, StartedAt: now.Add(-2 * time.Minute)},
		{ID: "s2", Status: "running", AssetCount: 5, FindingCount: 1, StartedAt: now.Add(-1 * time.Minute)},
	}
	sortScans(scans, "finding_count", false)
	if scans[0].ID != "s2" {
		t.Fatalf("expected finding_count asc sort, got %+v", scans)
	}
	sortScans(scans, "asset_count", true)
	if scans[0].ID != "s2" {
		t.Fatalf("expected asset_count desc sort, got %+v", scans)
	}
	sortScans(scans, "status", false)
	if scans[0].Status != "completed" {
		t.Fatalf("expected status asc sort, got %+v", scans)
	}

	events := []db.ScanEvent{
		{ID: "e1", Level: db.ScanEventLevelInfo, Message: "z", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "e2", Level: db.ScanEventLevelError, Message: "a", CreatedAt: now.Add(-1 * time.Minute)},
	}
	sortScanEvents(events, "level", true)
	if events[0].Level != db.ScanEventLevelError {
		t.Fatalf("expected level desc sort, got %+v", events)
	}
	sortScanEvents(events, "message", false)
	if events[0].Message != "a" {
		t.Fatalf("expected message asc sort, got %+v", events)
	}

	repoScans := []db.RepoScanRecord{
		{ID: "r1", Repository: "z/repo", Status: "completed", CommitsScanned: 10, FindingCount: 4, StartedAt: now.Add(-2 * time.Minute)},
		{ID: "r2", Repository: "a/repo", Status: "running", CommitsScanned: 3, FindingCount: 1, StartedAt: now.Add(-1 * time.Minute)},
	}
	sortRepoScans(repoScans, "repository", false)
	if repoScans[0].Repository != "a/repo" {
		t.Fatalf("expected repository asc sort, got %+v", repoScans)
	}
	sortRepoScans(repoScans, "commits_scanned", false)
	if repoScans[0].CommitsScanned != 3 {
		t.Fatalf("expected commits_scanned asc sort, got %+v", repoScans)
	}

	identities := []domain.Identity{
		{ID: "i1", Provider: domain.ProviderKubernetes, Type: domain.IdentityTypeServiceAccount, Name: "zeta", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "i2", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "alpha", CreatedAt: now.Add(-1 * time.Minute)},
	}
	sortIdentities(identities, "provider", false)
	if identities[0].Provider != domain.ProviderAWS {
		t.Fatalf("expected provider asc sort, got %+v", identities)
	}
	sortIdentities(identities, "type", false)
	if identities[0].Type != domain.IdentityTypeRole {
		t.Fatalf("expected type asc sort, got %+v", identities)
	}
	sortIdentities(identities, "created_at", true)
	if !identities[0].CreatedAt.After(identities[1].CreatedAt) {
		t.Fatalf("expected created_at desc sort, got %+v", identities)
	}

	relationships := []domain.Relationship{
		{ID: "x2", Type: domain.RelationshipCanAccess, FromNodeID: "z", ToNodeID: "a", DiscoveredAt: now.Add(-2 * time.Minute)},
		{ID: "x1", Type: domain.RelationshipCanAssume, FromNodeID: "a", ToNodeID: "z", DiscoveredAt: now.Add(-1 * time.Minute)},
	}
	sortRelationships(relationships, "type", false)
	if relationships[0].Type != domain.RelationshipCanAccess {
		t.Fatalf("expected type asc sort, got %+v", relationships)
	}
	sortRelationships(relationships, "from_node_id", false)
	if relationships[0].FromNodeID != "a" {
		t.Fatalf("expected from_node_id asc sort, got %+v", relationships)
	}
	sortRelationships(relationships, "to_node_id", false)
	if relationships[0].ToNodeID != "a" {
		t.Fatalf("expected to_node_id asc sort, got %+v", relationships)
	}

	ownership := []domain.OwnershipSignal{
		{ID: "o1", Team: "zeta", Source: "tags", Confidence: 0.5},
		{ID: "o2", Team: "alpha", Source: "owner_hint", Confidence: 0.9},
	}
	sortOwnershipSignals(ownership, "team", false)
	if ownership[0].Team != "alpha" {
		t.Fatalf("expected team asc sort, got %+v", ownership)
	}
	sortOwnershipSignals(ownership, "source", false)
	if ownership[0].Source != "owner_hint" {
		t.Fatalf("expected source asc sort, got %+v", ownership)
	}
	sortOwnershipSignals(ownership, "confidence", true)
	if ownership[0].Confidence < ownership[1].Confidence {
		t.Fatalf("expected confidence desc sort, got %+v", ownership)
	}

	if compareFloat(1.2, 1.2) != 0 {
		t.Fatal("expected compareFloat equality branch")
	}
}

func TestSecureKeyHelpers(t *testing.T) {
	if !secureKeyEquals("reader-secret", "reader-secret") {
		t.Fatal("expected equal keys to match")
	}
	if secureKeyEquals("reader-secret", "reader-secret-2") {
		t.Fatal("expected different keys to not match")
	}
	if keyInList([]string{"reader", "writer"}, "admin") {
		t.Fatal("expected missing key to not be found")
	}
	if !keyInList([]string{"reader", "writer"}, "writer") {
		t.Fatal("expected exact key to be found")
	}
	scoped := map[string]scopeSet{
		"reader": newScopeSet([]string{"read"}),
		"writer": newScopeSet([]string{"read", "write"}),
	}
	if _, ok := scopedKeyLookup(scoped, "missing"); ok {
		t.Fatal("expected missing scoped key to not resolve")
	}
	if scopes, ok := scopedKeyLookup(scoped, "writer"); !ok || !scopes.has("write") {
		t.Fatalf("expected writer scopes to resolve, got ok=%t scopes=%+v", ok, scopes)
	}
}

func varyHeaderContains(varyHeader string, value string) bool {
	for _, token := range strings.Split(varyHeader, ",") {
		if strings.EqualFold(strings.TrimSpace(token), strings.TrimSpace(value)) {
			return true
		}
	}
	return false
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

func TestRouterFindingTriageWorkflowEndpoints(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys:      []string{"read-key", "write-key"},
		WriteAPIKeys: []string{"write-key"},
	})

	triggerReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	triggerReq.Header.Set("X-API-Key", "write-key")
	triggerW := httptest.NewRecorder()
	r.ServeHTTP(triggerW, triggerReq)
	if triggerW.Code != http.StatusAccepted {
		t.Fatalf("expected scan trigger 202, got %d", triggerW.Code)
	}
	var triggerBody struct {
		Scan db.ScanRecord `json:"scan"`
	}
	if err := json.Unmarshal(triggerW.Body.Bytes(), &triggerBody); err != nil {
		t.Fatalf("decode scan trigger body: %v", err)
	}
	if triggerBody.Scan.ID == "" {
		t.Fatal("expected scan id in trigger response")
	}
	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan: %v", err)
	}
	if !processed {
		t.Fatal("expected one queued scan to be processed")
	}

	triagePayload := bytes.NewBufferString(`{"status":"ack","assignee":"platform","comment":"acknowledged for follow-up"}`)
	triageDeniedReq := httptest.NewRequest(http.MethodPatch, "/v1/findings/f1/triage?scan_id="+triggerBody.Scan.ID, bytes.NewBuffer(triagePayload.Bytes()))
	triageDeniedReq.Header.Set("Content-Type", "application/json")
	triageDeniedReq.Header.Set("X-API-Key", "read-key")
	triageDeniedW := httptest.NewRecorder()
	r.ServeHTTP(triageDeniedW, triageDeniedReq)
	if triageDeniedW.Code != http.StatusForbidden {
		t.Fatalf("expected read-key triage to be forbidden, got %d", triageDeniedW.Code)
	}

	triageReq := httptest.NewRequest(http.MethodPatch, "/v1/findings/f1/triage?scan_id="+triggerBody.Scan.ID, bytes.NewBuffer(triagePayload.Bytes()))
	triageReq.Header.Set("Content-Type", "application/json")
	triageReq.Header.Set("X-API-Key", "write-key")
	triageW := httptest.NewRecorder()
	r.ServeHTTP(triageW, triageReq)
	if triageW.Code != http.StatusOK {
		t.Fatalf("expected write-key triage to pass, got %d", triageW.Code)
	}

	var triageBody struct {
		Finding domain.Finding `json:"finding"`
	}
	if err := json.Unmarshal(triageW.Body.Bytes(), &triageBody); err != nil {
		t.Fatalf("decode triage body: %v", err)
	}
	if triageBody.Finding.Triage.Status != domain.FindingLifecycleAck {
		t.Fatalf("expected ack triage status, got %q", triageBody.Finding.Triage.Status)
	}
	if triageBody.Finding.Triage.Assignee != "platform" {
		t.Fatalf("expected platform assignee, got %q", triageBody.Finding.Triage.Assignee)
	}

	filteredReq := httptest.NewRequest(http.MethodGet, "/v1/findings?lifecycle_status=ack&assignee=platform", nil)
	filteredReq.Header.Set("X-API-Key", "read-key")
	filteredW := httptest.NewRecorder()
	r.ServeHTTP(filteredW, filteredReq)
	if filteredW.Code != http.StatusOK {
		t.Fatalf("expected filtered findings 200, got %d", filteredW.Code)
	}
	var filteredBody struct {
		Items []domain.Finding `json:"items"`
	}
	if err := json.Unmarshal(filteredW.Body.Bytes(), &filteredBody); err != nil {
		t.Fatalf("decode filtered findings body: %v", err)
	}
	if len(filteredBody.Items) != 1 || filteredBody.Items[0].ID != "f1" {
		t.Fatalf("unexpected filtered findings: %+v", filteredBody.Items)
	}

	historyReq := httptest.NewRequest(http.MethodGet, "/v1/findings/f1/history?scan_id="+triggerBody.Scan.ID, nil)
	historyReq.Header.Set("X-API-Key", "read-key")
	historyW := httptest.NewRecorder()
	r.ServeHTTP(historyW, historyReq)
	if historyW.Code != http.StatusOK {
		t.Fatalf("expected triage history 200, got %d", historyW.Code)
	}
	var historyBody struct {
		Items []db.FindingTriageEvent `json:"items"`
	}
	if err := json.Unmarshal(historyW.Body.Bytes(), &historyBody); err != nil {
		t.Fatalf("decode history body: %v", err)
	}
	if len(historyBody.Items) != 1 {
		t.Fatalf("expected one history event, got %d", len(historyBody.Items))
	}
	if historyBody.Items[0].Action != db.FindingTriageActionAcknowledged {
		t.Fatalf("expected acknowledged action, got %q", historyBody.Items[0].Action)
	}
	if historyBody.Items[0].Actor == "" {
		t.Fatalf("expected actor on history event, got %+v", historyBody.Items[0])
	}
}

func TestRouterWriteAuthorizationRequiresConfiguredWriteKeys(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		APIKeys: []string{"read-key"},
	})

	writeReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writeReq.Header.Set("X-API-Key", "read-key")
	writeW := httptest.NewRecorder()
	r.ServeHTTP(writeW, writeReq)
	if writeW.Code != http.StatusForbidden {
		t.Fatalf("expected write to be forbidden when no write keys are configured, got %d", writeW.Code)
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
			"writer-key": {scopeWrite},
			"bad-key":    {"invalid"},
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
	writeReq.Header.Set("X-API-Key", "writer-key")
	writeW := httptest.NewRecorder()
	r.ServeHTTP(writeW, writeReq)
	if writeW.Code != http.StatusAccepted {
		t.Fatalf("expected write with writer-key to pass, got %d", writeW.Code)
	}

	bearerFallbackReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	bearerFallbackReq.Header.Set("Authorization", "Bearer writer-key")
	bearerFallbackW := httptest.NewRecorder()
	r.ServeHTTP(bearerFallbackW, bearerFallbackReq)
	if bearerFallbackW.Code != http.StatusUnauthorized {
		t.Fatalf("expected bearer api-key fallback to be rejected, got %d", bearerFallbackW.Code)
	}

	badScopeReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	badScopeReq.Header.Set("X-API-Key", "bad-key")
	badScopeW := httptest.NewRecorder()
	r.ServeHTTP(badScopeW, badScopeReq)
	if badScopeW.Code != http.StatusForbidden {
		t.Fatalf("expected bad-key read to be forbidden, got %d", badScopeW.Code)
	}
}

func TestRouterOIDCOnlyAuthentication(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"good-token": {
					Subject:     "user-1",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"read"},
				},
				"no-scope-token": {
					Subject:     "user-2",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      nil,
				},
			},
		},
	})

	unauthReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	unauthW := httptest.NewRecorder()
	r.ServeHTTP(unauthW, unauthReq)
	if unauthW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", unauthW.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	authReq.Header.Set("Authorization", "Bearer good-token")
	authW := httptest.NewRecorder()
	r.ServeHTTP(authW, authReq)
	if authW.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid oidc token, got %d", authW.Code)
	}

	noScopeReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	noScopeReq.Header.Set("Authorization", "Bearer no-scope-token")
	noScopeW := httptest.NewRecorder()
	r.ServeHTTP(noScopeW, noScopeReq)
	if noScopeW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for oidc token without read scope, got %d", noScopeW.Code)
	}
}

func TestRouterOIDCWriteScopeAuthorization(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"reader-token": {
					Subject:     "user-read",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"identrail.read"},
				},
				"writer-token": {
					Subject:     "user-write",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"identrail.write"},
				},
			},
		},
		OIDCWriteScopes: []string{"identrail.write"},
	})

	readerWriteReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	readerWriteReq.Header.Set("Authorization", "Bearer reader-token")
	readerWriteW := httptest.NewRecorder()
	r.ServeHTTP(readerWriteW, readerWriteReq)
	if readerWriteW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only token on write path, got %d", readerWriteW.Code)
	}

	writerReq := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	writerReq.Header.Set("Authorization", "Bearer writer-token")
	writerW := httptest.NewRecorder()
	r.ServeHTTP(writerW, writerReq)
	if writerW.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for writer token, got %d", writerW.Code)
	}
}

func TestRouterHybridOIDCAndLegacyAPIKeyReadCompatibility(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	r := NewRouter(logger, metrics, nil, RouterOptions{
		APIKeys: []string{"legacy-key"},
		OIDCTokenVerifier: fakeTokenVerifier{
			tokens: map[string]VerifiedToken{
				"reader-token": {
					Subject:     "user-read",
					TenantID:    "tenant-1",
					WorkspaceID: "workspace-1",
					Scopes:      []string{"identrail.read"},
				},
			},
		},
	})

	readReq := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	readReq.Header.Set("X-API-Key", "legacy-key")
	readW := httptest.NewRecorder()
	r.ServeHTTP(readW, readReq)
	if readW.Code != http.StatusOK {
		t.Fatalf("expected legacy api key read to pass in hybrid mode, got %d", readW.Code)
	}
}

func TestRequestScopeMiddlewarePrefersOIDCTenantWorkspaceClaims(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth.tenant_id", "tenant-from-token")
		c.Set("auth.workspace_id", "workspace-from-token")
		c.Next()
	})
	r.Use(requestScopeMiddleware("default-tenant", "default-workspace"))
	r.GET("/scope", func(c *gin.Context) {
		scope := db.ScopeFromContext(c.Request.Context())
		c.JSON(http.StatusOK, map[string]string{
			"tenant_id":    scope.TenantID,
			"workspace_id": scope.WorkspaceID,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/scope", nil)
	req.Header.Set("X-Identrail-Tenant-ID", "header-tenant")
	req.Header.Set("X-Identrail-Workspace-ID", "header-workspace")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["tenant_id"] != "tenant-from-token" {
		t.Fatalf("expected tenant from oidc claim, got %q", body["tenant_id"])
	}
	if body["workspace_id"] != "workspace-from-token" {
		t.Fatalf("expected workspace from oidc claim, got %q", body["workspace_id"])
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

func TestIPRateLimiterEvictsExpiredEntries(t *testing.T) {
	now := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	limiter := newIPRateLimiterWithClock(
		60,
		1,
		func() time.Time { return now },
		1*time.Second,
		2,
		1,
	)

	if !limiter.allow("10.0.0.1") {
		t.Fatal("expected first request to pass")
	}
	if len(limiter.limiters) != 1 {
		t.Fatalf("expected one tracked ip, got %d", len(limiter.limiters))
	}

	now = now.Add(2 * time.Second)
	if !limiter.allow("10.0.0.2") {
		t.Fatal("expected new request to pass")
	}
	if len(limiter.limiters) != 1 {
		t.Fatalf("expected stale entry eviction to keep one tracked ip, got %d", len(limiter.limiters))
	}
	if _, exists := limiter.limiters["10.0.0.1"]; exists {
		t.Fatal("expected expired ip entry to be evicted")
	}
}

func TestIPRateLimiterEvictsOldestEntryWhenCapacityReached(t *testing.T) {
	now := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	limiter := newIPRateLimiterWithClock(
		60,
		1,
		func() time.Time { return now },
		1*time.Hour,
		2,
		1,
	)

	if !limiter.allow("10.0.0.1") {
		t.Fatal("expected first request to pass")
	}
	now = now.Add(100 * time.Millisecond)
	if !limiter.allow("10.0.0.2") {
		t.Fatal("expected second request to pass")
	}
	now = now.Add(100 * time.Millisecond)
	if !limiter.allow("10.0.0.3") {
		t.Fatal("expected third request to pass")
	}
	if len(limiter.limiters) != 2 {
		t.Fatalf("expected limiter size to stay bounded at 2, got %d", len(limiter.limiters))
	}
	if _, exists := limiter.limiters["10.0.0.1"]; exists {
		t.Fatal("expected oldest entry to be evicted when capacity is reached")
	}
	if _, exists := limiter.limiters["10.0.0.2"]; !exists {
		t.Fatal("expected newer entry to remain in limiter cache")
	}
	if _, exists := limiter.limiters["10.0.0.3"]; !exists {
		t.Fatal("expected most recent entry to remain in limiter cache")
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
	r := NewRouter(logger, metrics, nil, RouterOptions{
		AuditSink:    sink,
		APIKeyScopes: map[string][]string{"reader-key": {"read"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	req.RemoteAddr = "127.0.0.1:34567"
	req.Header.Set("User-Agent", "router-test")
	req.Header.Set("X-API-Key", "reader-key")
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
	if event.APIKeyID == "" {
		t.Fatal("expected api key fingerprint in audit event")
	}
	if event.APIKeyID == "reader-key" {
		t.Fatal("expected fingerprint instead of raw api key")
	}
}

func TestRouterScanDiffAndEventsNotFound(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	diffReq := httptest.NewRequest(http.MethodGet, "/v1/scans/missing/diff", nil)
	diffW := httptest.NewRecorder()
	r.ServeHTTP(diffW, diffReq)
	if diffW.Code != http.StatusNotFound {
		t.Fatalf("expected diff 404 for missing scan, got %d", diffW.Code)
	}

	eventsReq := httptest.NewRequest(http.MethodGet, "/v1/scans/missing/events", nil)
	eventsW := httptest.NewRecorder()
	r.ServeHTTP(eventsW, eventsReq)
	if eventsW.Code != http.StatusNotFound {
		t.Fatalf("expected events 404 for missing scan, got %d", eventsW.Code)
	}

	identitiesReq := httptest.NewRequest(http.MethodGet, "/v1/identities?scan_id=missing", nil)
	identitiesW := httptest.NewRecorder()
	r.ServeHTTP(identitiesW, identitiesReq)
	if identitiesW.Code != http.StatusNotFound {
		t.Fatalf("expected identities 404 for missing scan, got %d", identitiesW.Code)
	}

	relationshipsReq := httptest.NewRequest(http.MethodGet, "/v1/relationships?scan_id=missing", nil)
	relationshipsW := httptest.NewRecorder()
	r.ServeHTTP(relationshipsW, relationshipsReq)
	if relationshipsW.Code != http.StatusNotFound {
		t.Fatalf("expected relationships 404 for missing scan, got %d", relationshipsW.Code)
	}

	findingsReq := httptest.NewRequest(http.MethodGet, "/v1/findings?scan_id=missing", nil)
	findingsW := httptest.NewRecorder()
	r.ServeHTTP(findingsW, findingsReq)
	if findingsW.Code != http.StatusNotFound {
		t.Fatalf("expected findings 404 for missing scan, got %d", findingsW.Code)
	}

	findingReq := httptest.NewRequest(http.MethodGet, "/v1/findings/missing", nil)
	findingW := httptest.NewRecorder()
	r.ServeHTTP(findingW, findingReq)
	if findingW.Code != http.StatusNotFound {
		t.Fatalf("expected finding-by-id 404 for missing finding, got %d", findingW.Code)
	}

	scan, err := store.CreateScan(defaultScopeContext(), "aws", time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	invalidBaselineReq := httptest.NewRequest(
		http.MethodGet,
		"/v1/scans/"+scan.ID+"/diff?previous_scan_id="+scan.ID,
		nil,
	)
	invalidBaselineW := httptest.NewRecorder()
	r.ServeHTTP(invalidBaselineW, invalidBaselineReq)
	if invalidBaselineW.Code != http.StatusBadRequest {
		t.Fatalf("expected diff 400 for invalid baseline scan, got %d", invalidBaselineW.Code)
	}
}

func TestRouterRejectsInvalidRepoScanUUIDInputs(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	metrics := telemetry.NewMetrics()
	store := db.NewMemoryStore()
	svc := NewService(store, routerScanner{}, "aws")
	r := NewRouter(logger, metrics, svc, RouterOptions{})

	repoScanReq := httptest.NewRequest(http.MethodGet, "/v1/repo-scans/not-a-uuid", nil)
	repoScanW := httptest.NewRecorder()
	r.ServeHTTP(repoScanW, repoScanReq)
	if repoScanW.Code != http.StatusBadRequest {
		t.Fatalf("expected repo scan detail 400 for invalid repo_scan_id, got %d", repoScanW.Code)
	}

	repoFindingsReq := httptest.NewRequest(http.MethodGet, "/v1/repo-findings?repo_scan_id=not-a-uuid", nil)
	repoFindingsW := httptest.NewRecorder()
	r.ServeHTTP(repoFindingsW, repoFindingsReq)
	if repoFindingsW.Code != http.StatusBadRequest {
		t.Fatalf("expected repo findings 400 for invalid repo_scan_id filter, got %d", repoFindingsW.Code)
	}
}

func TestRouterPaginationHelpers(t *testing.T) {
	if got := parseCursor(""); got != 0 {
		t.Fatalf("expected empty cursor to parse as 0, got %d", got)
	}
	if got := parseCursor("bad"); got != 0 {
		t.Fatalf("expected invalid cursor to parse as 0, got %d", got)
	}
	if got := parseCursor("12"); got != 12 {
		t.Fatalf("expected cursor 12, got %d", got)
	}
	items := []int{1, 2, 3}
	page, next := pageWithCursor(items, 0, 2)
	if len(page) != 2 || next != "2" {
		t.Fatalf("unexpected page result page=%+v next=%q", page, next)
	}
	page, next = pageWithCursor(items, 2, 2)
	if len(page) != 1 || next != "" {
		t.Fatalf("unexpected final page result page=%+v next=%q", page, next)
	}
}
