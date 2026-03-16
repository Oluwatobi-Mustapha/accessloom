package db

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
	"github.com/google/uuid"
)

// MemoryStore is a concurrency-safe in-memory persistence adapter.
type MemoryStore struct {
	mu       sync.RWMutex
	scans    map[string]ScanRecord
	scanIDs  []string
	findings map[string]domain.Finding
	events   map[string][]ScanEvent

	rawAssets     map[string]providers.RawAsset
	identities    map[string]domain.Identity
	policies      map[string]domain.Policy
	relationships map[string]domain.Relationship
	permissions   map[string]providers.PermissionTuple
}

// NewMemoryStore initializes an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:    map[string]ScanRecord{},
		scanIDs:  []string{},
		findings: map[string]domain.Finding{},
		events:   map[string][]ScanEvent{},

		rawAssets:     map[string]providers.RawAsset{},
		identities:    map[string]domain.Identity{},
		policies:      map[string]domain.Policy{},
		relationships: map[string]domain.Relationship{},
		permissions:   map[string]providers.PermissionTuple{},
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

// GetScan returns one persisted scan by id.
func (m *MemoryStore) GetScan(_ context.Context, scanID string) (ScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	record, exists := m.scans[scanID]
	if !exists {
		return ScanRecord{}, ErrNotFound
	}
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

// UpsertArtifacts persists raw and normalized scan artifacts idempotently.
func (m *MemoryStore) UpsertArtifacts(_ context.Context, scanID string, artifacts ScanArtifacts) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.scans[scanID]; !exists {
		return fmt.Errorf("scan %s not found", scanID)
	}

	for _, asset := range artifacts.RawAssets {
		key := scanID + "|" + asset.SourceID + "|" + asset.Kind
		m.rawAssets[key] = asset
	}
	for _, identity := range artifacts.Bundle.Identities {
		key := scanID + "|" + identity.ID
		m.identities[key] = identity
	}
	for _, policy := range artifacts.Bundle.Policies {
		key := scanID + "|" + policy.ID
		m.policies[key] = policy
	}
	for _, relationship := range artifacts.Relationships {
		key := scanID + "|" + relationship.ID
		m.relationships[key] = relationship
	}
	for _, permission := range artifacts.Permissions {
		key := scanID + "|" + permission.IdentityID + "|" + permission.Action + "|" + permission.Resource + "|" + permission.Effect
		m.permissions[key] = permission
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

// ListFindingsByScan returns latest findings first for one scan.
func (m *MemoryStore) ListFindingsByScan(_ context.Context, scanID string, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.scans[scanID]; !exists {
		return nil, ErrNotFound
	}

	result := []domain.Finding{}
	for _, finding := range m.findings {
		if finding.ScanID != scanID {
			continue
		}
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

// AppendScanEvent appends one scan event entry.
func (m *MemoryStore) AppendScanEvent(_ context.Context, scanID string, level string, message string, metadata map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.scans[scanID]; !exists {
		return ErrNotFound
	}
	m.events[scanID] = append(m.events[scanID], ScanEvent{
		ID:        uuid.NewString(),
		ScanID:    scanID,
		Level:     level,
		Message:   message,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC(),
	})
	return nil
}

// ListScanEvents returns most recent scan events first.
func (m *MemoryStore) ListScanEvents(_ context.Context, scanID string, limit int) ([]ScanEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.scans[scanID]; !exists {
		return nil, ErrNotFound
	}
	events := append([]ScanEvent(nil), m.events[scanID]...)
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// Close closes store resources.
func (m *MemoryStore) Close() error {
	return nil
}
