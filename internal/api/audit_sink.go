package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	APIKeyID   string    `json:"api_key_id,omitempty"`
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

// HTTPAuditSink posts audit events to a remote collector endpoint.
type HTTPAuditSink struct {
	client     *http.Client
	url        string
	hmacSecret string
}

// NewHTTPAuditSink builds an HTTP audit sink with URL safety checks.
func NewHTTPAuditSink(endpoint string, timeout time.Duration, hmacSecret string) (*HTTPAuditSink, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return nil, fmt.Errorf("audit forward url is required")
	}
	if err := validateAuditForwardURL(trimmed); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPAuditSink{
		client:     &http.Client{Timeout: timeout},
		url:        trimmed,
		hmacSecret: strings.TrimSpace(hmacSecret),
	}, nil
}

func (s *HTTPAuditSink) Write(event AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build audit forward request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "identrail-audit/1.0")
	if s.hmacSecret != "" {
		req.Header.Set("X-Identrail-Signature", computeHMAC(payload, s.hmacSecret))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send audit event: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("audit forward status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *HTTPAuditSink) Close() error { return nil }

// MultiAuditSink fans out one event to multiple sinks.
type MultiAuditSink struct {
	sinks []AuditSink
}

// NewMultiAuditSink creates a fanout sink.
func NewMultiAuditSink(sinks ...AuditSink) *MultiAuditSink {
	filtered := make([]AuditSink, 0, len(sinks))
	for _, sink := range sinks {
		if sink == nil {
			continue
		}
		filtered = append(filtered, sink)
	}
	return &MultiAuditSink{sinks: filtered}
}

func (m *MultiAuditSink) Write(event AuditEvent) error {
	var firstErr error
	for _, sink := range m.sinks {
		if err := sink.Write(event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiAuditSink) Close() error {
	var firstErr error
	for _, sink := range m.sinks {
		if err := sink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func fingerprintAPIKey(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	// Truncated, deterministic identifier for correlation without exposing key material.
	return "sha256:" + hex.EncodeToString(sum[:6])
}

func validateAuditForwardURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse audit forward url: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("insecure audit forward url scheme http is only allowed for localhost")
	default:
		return fmt.Errorf("unsupported audit forward url scheme %q", parsed.Scheme)
	}
}
