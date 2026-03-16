package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testRecordingAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *testRecordingAuditSink) Write(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (*testRecordingAuditSink) Close() error { return nil }

func TestFileAuditSinkWritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("new file audit sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	event := AuditEvent{
		Timestamp:  time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC),
		Method:     "GET",
		Path:       "/v1/scans",
		Status:     200,
		ClientIP:   "127.0.0.1",
		DurationMS: 4,
		UserAgent:  "test",
		APIKeyID:   fingerprintAPIKey("reader-key"),
	}
	if err := sink.Write(event); err != nil {
		t.Fatalf("write audit event: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	var got AuditEvent
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode audit json: %v; payload=%s", err, string(data))
	}
	if got.Path != event.Path || got.Method != event.Method || got.Status != event.Status {
		t.Fatalf("unexpected event payload: %+v", got)
	}
}

func TestFileAuditSinkConstructorError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "audit.log")
	if _, err := NewFileAuditSink(path); err == nil {
		t.Fatal("expected constructor error")
	}
}

func TestHTTPAuditSinkWritesEvent(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("X-Identrail-Signature"); got == "" {
			t.Fatal("expected signature header")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sink, err := NewHTTPAuditSink(server.URL, 2*time.Second, "secret")
	if err != nil {
		t.Fatalf("new http audit sink: %v", err)
	}
	err = sink.Write(AuditEvent{Method: "GET", Path: "/v1/scans", Timestamp: time.Now().UTC()})
	if err != nil {
		t.Fatalf("write http audit event: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected 1 request, got %d", requests)
	}
}

func TestHTTPAuditSinkRejectsInsecureURL(t *testing.T) {
	if _, err := NewHTTPAuditSink("http://example.com/audit", 2*time.Second, ""); err == nil {
		t.Fatal("expected insecure url error")
	}
}

func TestMultiAuditSinkFanout(t *testing.T) {
	record := &testRecordingAuditSink{}
	multi := NewMultiAuditSink(record, NopAuditSink{})
	if err := multi.Write(AuditEvent{Method: "GET", Path: "/v1/scans"}); err != nil {
		t.Fatalf("write fanout event: %v", err)
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if len(record.events) != 1 {
		t.Fatalf("expected 1 event in fanout sink, got %d", len(record.events))
	}
}

func TestFingerprintAPIKey(t *testing.T) {
	a := fingerprintAPIKey("secret-key")
	b := fingerprintAPIKey("secret-key")
	c := fingerprintAPIKey("different-key")
	if a == "" {
		t.Fatal("expected fingerprint")
	}
	if a != b {
		t.Fatalf("expected deterministic fingerprint, got %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("expected different fingerprints, got %q and %q", a, c)
	}
	if a == "secret-key" {
		t.Fatal("fingerprint should not equal raw key")
	}
}
