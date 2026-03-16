package api

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEvent captures one API request for external audit export.
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	ClientIP   string    `json:"client_ip"`
	DurationMS int64     `json:"duration_ms"`
	UserAgent  string    `json:"user_agent"`
	APIKey     string    `json:"api_key,omitempty"`
}

// AuditSink defines the export target for API audit events.
type AuditSink interface {
	Write(event AuditEvent) error
	Close() error
}

// NopAuditSink discards audit events when no export target is configured.
type NopAuditSink struct{}

func (NopAuditSink) Write(AuditEvent) error { return nil }
func (NopAuditSink) Close() error           { return nil }

// FileAuditSink writes audit events in JSON lines format.
type FileAuditSink struct {
	mu   sync.Mutex
	file *os.File
}

// NewFileAuditSink creates or appends to a local audit file with restrictive permissions.
func NewFileAuditSink(path string) (*FileAuditSink, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log file: %w", err)
	}
	return &FileAuditSink{file: file}, nil
}

func (s *FileAuditSink) Write(event AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}
