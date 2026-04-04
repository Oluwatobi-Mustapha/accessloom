package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
	"github.com/google/uuid"
)

// MemoryStore is a concurrency-safe in-memory persistence adapter.
type MemoryStore struct {
	mu           sync.RWMutex
	scans        map[string]ScanRecord
	scanIDs      []string
	findings     map[string]domain.Finding
	events       map[string][]ScanEvent
	repoScans    map[string]RepoScanRecord
	repoScanIDs  []string
	repoFindings map[string]domain.Finding

	rawAssets     map[string]providers.RawAsset
	identities    map[string]domain.Identity
	policies      map[string]domain.Policy
	relationships map[string]domain.Relationship
	permissions   map[string]providers.PermissionTuple
}

// NewMemoryStore initializes an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:        map[string]ScanRecord{},
		scanIDs:      []string{},
		findings:     map[string]domain.Finding{},
		events:       map[string][]ScanEvent{},
		repoScans:    map[string]RepoScanRecord{},
		repoScanIDs:  []string{},
		repoFindings: map[string]domain.Finding{},

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

	return m.createScanLocked(provider, "running", startedAt), nil
}

// CreateQueuedScan persists one queued scan request.
func (m *MemoryStore) CreateQueuedScan(_ context.Context, provider string, queuedAt time.Time) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.createScanLocked(provider, "queued", queuedAt), nil
}

// ClaimNextQueuedScan moves one queued scan to running for execution.
func (m *MemoryStore) ClaimNextQueuedScan(_ context.Context, provider string) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalizedProvider := strings.TrimSpace(provider)
	found := false
	var bestRecord ScanRecord
	for _, scanID := range m.scanIDs {
		record := m.scans[scanID]
		if record.Status != "queued" {
			continue
		}
		if normalizedProvider != "" && strings.TrimSpace(record.Provider) != normalizedProvider {
			continue
		}
		if !found || record.StartedAt.Before(bestRecord.StartedAt) {
			bestRecord = record
			found = true
		}
	}
	if !found {
		return ScanRecord{}, ErrNotFound
	}
	bestRecord.Status = "running"
	bestRecord.FinishedAt = nil
	bestRecord.ErrorMessage = ""
	m.scans[bestRecord.ID] = bestRecord
	return bestRecord, nil
}

// CountQueuedScans returns the queued scan count for one provider.
func (m *MemoryStore) CountQueuedScans(_ context.Context, provider string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normalizedProvider := strings.TrimSpace(provider)
	count := 0
	for _, record := range m.scans {
		if record.Status != "queued" {
			continue
		}
		if normalizedProvider != "" && strings.TrimSpace(record.Provider) != normalizedProvider {
			continue
		}
		count++
	}
	return count, nil
}

func (m *MemoryStore) createScanLocked(provider string, status string, startedAt time.Time) ScanRecord {
	record := ScanRecord{
		ID:        uuid.NewString(),
		Provider:  strings.TrimSpace(provider),
		Status:    strings.TrimSpace(status),
		StartedAt: startedAt.UTC(),
	}
	m.scans[record.ID] = record
	m.scanIDs = append(m.scanIDs, record.ID)
	return record
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

// ListIdentities returns identities filtered by scan/provider/type/name.
func (m *MemoryStore) ListIdentities(_ context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filteredScanID := strings.TrimSpace(filter.ScanID)
	if filteredScanID != "" {
		if _, exists := m.scans[filteredScanID]; !exists {
			return nil, ErrNotFound
		}
	}

	namePrefix := strings.ToLower(strings.TrimSpace(filter.NamePrefix))
	provider := strings.ToLower(strings.TrimSpace(filter.Provider))
	identityType := strings.ToLower(strings.TrimSpace(filter.Type))
	result := []domain.Identity{}
	for key, identity := range m.identities {
		scanID := scanKeyPrefix(key)
		if filteredScanID != "" && scanID != filteredScanID {
			continue
		}
		if provider != "" && strings.ToLower(string(identity.Provider)) != provider {
			continue
		}
		if identityType != "" && strings.ToLower(string(identity.Type)) != identityType {
			continue
		}
		if namePrefix != "" && !strings.HasPrefix(strings.ToLower(identity.Name), namePrefix) {
			continue
		}
		result = append(result, identity)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// ListRelationships returns relationships filtered by scan/type/from/to.
func (m *MemoryStore) ListRelationships(_ context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filteredScanID := strings.TrimSpace(filter.ScanID)
	if filteredScanID != "" {
		if _, exists := m.scans[filteredScanID]; !exists {
			return nil, ErrNotFound
		}
	}
	relType := strings.ToLower(strings.TrimSpace(filter.Type))
	fromNode := strings.TrimSpace(filter.FromNodeID)
	toNode := strings.TrimSpace(filter.ToNodeID)

	result := []domain.Relationship{}
	for key, relationship := range m.relationships {
		scanID := scanKeyPrefix(key)
		if filteredScanID != "" && scanID != filteredScanID {
			continue
		}
		if relType != "" && strings.ToLower(string(relationship.Type)) != relType {
			continue
		}
		if fromNode != "" && relationship.FromNodeID != fromNode {
			continue
		}
		if toNode != "" && relationship.ToNodeID != toNode {
			continue
		}
		result = append(result, relationship)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DiscoveredAt.After(result[j].DiscoveredAt) })
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
	normalizedLevel, err := NormalizeScanEventLevel(strings.ToLower(strings.TrimSpace(level)))
	if err != nil {
		return err
	}
	m.events[scanID] = append(m.events[scanID], ScanEvent{
		ID:        uuid.NewString(),
		ScanID:    scanID,
		Level:     normalizedLevel,
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

func scanKeyPrefix(key string) string {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// CreateRepoScan persists one repository exposure scan start event.
func (m *MemoryStore) CreateRepoScan(_ context.Context, repository string, startedAt time.Time) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.createRepoScanLocked(strings.TrimSpace(repository), "running", 0, 0, startedAt), nil
}

// CreateQueuedRepoScan persists one queued repository exposure scan request.
func (m *MemoryStore) CreateQueuedRepoScan(_ context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.createRepoScanLocked(strings.TrimSpace(repository), "queued", historyLimit, maxFindings, queuedAt), nil
}

// ClaimNextQueuedRepoScan moves one queued repository scan to running for execution.
func (m *MemoryStore) ClaimNextQueuedRepoScan(_ context.Context) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var claimed RepoScanRecord
	found := false
	for _, scanID := range m.repoScanIDs {
		record := m.repoScans[scanID]
		if record.Status != "queued" {
			continue
		}
		if !found || record.StartedAt.Before(claimed.StartedAt) {
			claimed = record
			found = true
		}
	}
	if !found {
		return RepoScanRecord{}, ErrNotFound
	}
	claimed.Status = "running"
	claimed.FinishedAt = nil
	claimed.ErrorMessage = ""
	m.repoScans[claimed.ID] = claimed
	return claimed, nil
}

// CountQueuedRepoScans returns queued repository scan count.
func (m *MemoryStore) CountQueuedRepoScans(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, record := range m.repoScans {
		if record.Status == "queued" {
			count++
		}
	}
	return count, nil
}

// CountPendingRepoScansByRepository returns queued/running scan count for one repository.
func (m *MemoryStore) CountPendingRepoScansByRepository(_ context.Context, repository string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normalizedRepository := strings.TrimSpace(repository)
	if normalizedRepository == "" {
		return 0, nil
	}
	count := 0
	for _, record := range m.repoScans {
		if strings.TrimSpace(record.Repository) != normalizedRepository {
			continue
		}
		if record.Status == "queued" || record.Status == "running" {
			count++
		}
	}
	return count, nil
}

// RequeueRepoScan moves a running repository scan back to queued state.
func (m *MemoryStore) RequeueRepoScan(_ context.Context, repoScanID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	record, exists := m.repoScans[repoScanID]
	if !exists {
		return ErrNotFound
	}
	if record.Status != "running" {
		return ErrNotFound
	}
	record.Status = "queued"
	record.StartedAt = time.Now().UTC()
	record.FinishedAt = nil
	record.ErrorMessage = ""
	m.repoScans[repoScanID] = record
	return nil
}

func (m *MemoryStore) createRepoScanLocked(repository string, status string, historyLimit int, maxFindings int, startedAt time.Time) RepoScanRecord {
	record := RepoScanRecord{
		ID:           uuid.NewString(),
		Repository:   strings.TrimSpace(repository),
		Status:       strings.TrimSpace(status),
		StartedAt:    startedAt.UTC(),
		HistoryLimit: historyLimit,
		MaxFindings:  maxFindings,
	}
	m.repoScans[record.ID] = record
	m.repoScanIDs = append(m.repoScanIDs, record.ID)
	return record
}

// GetRepoScan returns one persisted repo scan by id.
func (m *MemoryStore) GetRepoScan(_ context.Context, repoScanID string) (RepoScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	record, exists := m.repoScans[repoScanID]
	if !exists {
		return RepoScanRecord{}, ErrNotFound
	}
	return record, nil
}

// CompleteRepoScan finalizes repo scan metadata.
func (m *MemoryStore) CompleteRepoScan(_ context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	record, exists := m.repoScans[repoScanID]
	if !exists {
		return ErrNotFound
	}
	finished := finishedAt.UTC()
	record.Status = strings.TrimSpace(status)
	record.FinishedAt = &finished
	record.CommitsScanned = commitsScanned
	record.FilesScanned = filesScanned
	record.FindingCount = findingCount
	record.Truncated = truncated
	record.ErrorMessage = strings.TrimSpace(errorMessage)
	m.repoScans[repoScanID] = record
	return nil
}

// UpsertRepoFindings persists repository findings idempotently by repo_scan_id + finding_id.
func (m *MemoryStore) UpsertRepoFindings(_ context.Context, repoScanID string, findings []domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.repoScans[repoScanID]; !exists {
		return ErrNotFound
	}
	for _, finding := range findings {
		finding.ScanID = repoScanID
		key := repoScanID + "|" + finding.ID
		m.repoFindings[key] = finding
	}
	return nil
}

// ListRepoScans returns latest repo scans first.
func (m *MemoryStore) ListRepoScans(_ context.Context, limit int) ([]RepoScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]RepoScanRecord, 0, len(m.repoScanIDs))
	for _, scanID := range m.repoScanIDs {
		result = append(result, m.repoScans[scanID])
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].StartedAt.After(result[j].StartedAt)
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// ListRepoFindings returns repository findings using optional filters.
func (m *MemoryStore) ListRepoFindings(_ context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	repoScanID := strings.TrimSpace(filter.RepoScanID)
	if repoScanID != "" {
		if _, exists := m.repoScans[repoScanID]; !exists {
			return nil, ErrNotFound
		}
	}
	severity := strings.ToLower(strings.TrimSpace(filter.Severity))
	findingType := strings.ToLower(strings.TrimSpace(filter.Type))

	result := make([]domain.Finding, 0, len(m.repoFindings))
	for _, finding := range m.repoFindings {
		if repoScanID != "" && finding.ScanID != repoScanID {
			continue
		}
		if severity != "" && strings.ToLower(string(finding.Severity)) != severity {
			continue
		}
		if findingType != "" && strings.ToLower(string(finding.Type)) != findingType {
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

// Close closes store resources.
func (m *MemoryStore) Close() error {
	return nil
}
