package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
		APIKey:     "reader-key",
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
