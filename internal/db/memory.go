package db

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/google/uuid"
)

// MemoryStore is a concurrency-safe in-memory persistence adapter.
type MemoryStore struct {
	mu       sync.RWMutex
	scans    map[string]ScanRecord
	scanIDs  []string
	findings map[string]domain.Finding
}

// NewMemoryStore initializes an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:    map[string]ScanRecord{},
		scanIDs:  []string{},
		findings: map[string]domain.Finding{},
	}
}

// CreateScan persists a scan start event.
func (m *MemoryStore) CreateScan(_ context.Context, provider string, startedAt time.Time) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	record := ScanRecord{
		ID:        uuid.NewString(),
		Provider:  provider,
		Status:    "running",
		StartedAt: startedAt.UTC(),
	}
	m.scans[record.ID] = record
	m.scanIDs = append(m.scanIDs, record.ID)
	return record, nil
}

// CompleteScan finalizes persisted scan metadata.
func (m *MemoryStore) CompleteScan(_ context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	record, exists := m.scans[scanID]
	if !exists {
		return fmt.Errorf("scan %s not found", scanID)
	}
	finished := finishedAt.UTC()
	record.Status = status
	record.FinishedAt = &finished
	record.AssetCount = assetCount
	record.FindingCount = findingCount
	record.ErrorMessage = errorMessage
	m.scans[scanID] = record
	return nil
}

// UpsertFindings persists findings idempotently by scan_id + finding_id.
func (m *MemoryStore) UpsertFindings(_ context.Context, scanID string, findings []domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.scans[scanID]; !exists {
		return fmt.Errorf("scan %s not found", scanID)
	}

	for _, finding := range findings {
		finding.ScanID = scanID
		key := scanID + "|" + finding.ID
		m.findings[key] = finding
	}
	return nil
}

// ListScans returns latest scans first.
func (m *MemoryStore) ListScans(_ context.Context, limit int) ([]ScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	records := make([]ScanRecord, 0, len(m.scanIDs))
	for _, scanID := range m.scanIDs {
		records = append(records, m.scans[scanID])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].StartedAt.After(records[j].StartedAt)
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

// ListFindings returns latest findings first.
func (m *MemoryStore) ListFindings(_ context.Context, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]domain.Finding, 0, len(m.findings))
	for _, finding := range m.findings {
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// Close closes store resources.
func (m *MemoryStore) Close() error {
	return nil
}
