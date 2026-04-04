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
	triageStates map[string]FindingTriageState
	triageEvents map[string][]FindingTriageEvent
	events       map[string][]ScanEvent
	repoScans    map[string]RepoScanRecord
	repoScanIDs  []string
	repoFindings map[string]domain.Finding

	rawAssets     map[string]providers.RawAsset
	identities    map[string]domain.Identity
	policies      map[string]domain.Policy
	relationships map[string]domain.Relationship
	permissions   map[string]providers.PermissionTuple

	rbacRoles       map[string]RBACRole
	rbacRoleByName  map[string]string
	rbacRolePerms   map[string][]string
	rbacBindings    map[string]RBACBinding
	rbacBindingByID []string
}

// NewMemoryStore initializes an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:        map[string]ScanRecord{},
		scanIDs:      []string{},
		findings:     map[string]domain.Finding{},
		triageStates: map[string]FindingTriageState{},
		triageEvents: map[string][]FindingTriageEvent{},
		events:       map[string][]ScanEvent{},
		repoScans:    map[string]RepoScanRecord{},
		repoScanIDs:  []string{},
		repoFindings: map[string]domain.Finding{},

		rawAssets:     map[string]providers.RawAsset{},
		identities:    map[string]domain.Identity{},
		policies:      map[string]domain.Policy{},
		relationships: map[string]domain.Relationship{},
		permissions:   map[string]providers.PermissionTuple{},

		rbacRoles:       map[string]RBACRole{},
		rbacRoleByName:  map[string]string{},
		rbacRolePerms:   map[string][]string{},
		rbacBindings:    map[string]RBACBinding{},
		rbacBindingByID: []string{},
	}
}

// CreateScan persists a scan start event.
func (m *MemoryStore) CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	return m.createScanLocked(scope, provider, "running", startedAt), nil
}

// CreateQueuedScan persists one queued scan request.
func (m *MemoryStore) CreateQueuedScan(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	return m.createScanLocked(scope, provider, "queued", queuedAt), nil
}

// ClaimNextQueuedScan moves one queued scan to running for execution.
func (m *MemoryStore) ClaimNextQueuedScan(ctx context.Context, provider string) (ScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	normalizedProvider := strings.TrimSpace(provider)
	found := false
	var bestRecord ScanRecord
	for _, scanID := range m.scanIDs {
		record := m.scans[scanID]
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
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
func (m *MemoryStore) CountQueuedScans(ctx context.Context, provider string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	normalizedProvider := strings.TrimSpace(provider)
	count := 0
	for _, record := range m.scans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
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

func (m *MemoryStore) createScanLocked(scope Scope, provider string, status string, startedAt time.Time) ScanRecord {
	normalizedScope := scope.Normalize()
	record := ScanRecord{
		ID:          uuid.NewString(),
		TenantID:    normalizedScope.TenantID,
		WorkspaceID: normalizedScope.WorkspaceID,
		Provider:    strings.TrimSpace(provider),
		Status:      strings.TrimSpace(status),
		StartedAt:   startedAt.UTC(),
	}
	m.scans[record.ID] = record
	m.scanIDs = append(m.scanIDs, record.ID)
	return record
}

// GetScan returns one persisted scan by id.
func (m *MemoryStore) GetScan(ctx context.Context, scanID string) (ScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	record, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ScanRecord{}, ErrNotFound
	}
	return record, nil
}

// CompleteScan finalizes persisted scan metadata.
func (m *MemoryStore) CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return ErrNotFound
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
func (m *MemoryStore) UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return ErrNotFound
	}

	for _, finding := range findings {
		finding.ScanID = scanID
		key := scanID + "|" + finding.ID
		m.findings[key] = finding
	}
	return nil
}

// GetFindingTriageState returns triage workflow state for one finding id.
func (m *MemoryStore) GetFindingTriageState(ctx context.Context, findingID string) (FindingTriageState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return FindingTriageState{}, err
	}
	state, exists := m.triageStates[findingScopeKey(scope, findingID)]
	if !exists {
		return FindingTriageState{}, ErrNotFound
	}
	return state, nil
}

// ListFindingTriageStates returns triage states for provided finding ids.
func (m *MemoryStore) ListFindingTriageStates(ctx context.Context, findingIDs []string) ([]FindingTriageState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	result := make([]FindingTriageState, 0, len(findingIDs))
	for _, findingID := range findingIDs {
		normalized := strings.TrimSpace(findingID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		state, exists := m.triageStates[findingScopeKey(scope, normalized)]
		if !exists {
			continue
		}
		result = append(result, state)
	}
	return result, nil
}

// UpsertFindingTriageState creates or updates mutable triage metadata.
func (m *MemoryStore) UpsertFindingTriageState(ctx context.Context, state FindingTriageState) error {
	normalized, err := normalizeFindingTriageStateForWrite(state)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.triageStates[findingScopeKey(scope, normalized.FindingID)] = normalized
	return nil
}

// AppendFindingTriageEvent records one immutable triage action.
func (m *MemoryStore) AppendFindingTriageEvent(ctx context.Context, event FindingTriageEvent) error {
	normalized, err := normalizeFindingTriageEventForWrite(event)
	if err != nil {
		return err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := findingScopeKey(scope, normalized.FindingID)
	m.triageEvents[key] = append(m.triageEvents[key], normalized)
	return nil
}

// ApplyFindingTriageTransition persists state and audit history atomically.
func (m *MemoryStore) ApplyFindingTriageTransition(ctx context.Context, state FindingTriageState, event FindingTriageEvent) error {
	normalizedState, err := normalizeFindingTriageStateForWrite(state)
	if err != nil {
		return err
	}
	normalizedEvent, err := normalizeFindingTriageEventForWrite(event)
	if err != nil {
		return err
	}
	if normalizedState.FindingID != normalizedEvent.FindingID {
		return fmt.Errorf("finding id mismatch between state and event")
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	key := findingScopeKey(scope, normalizedState.FindingID)
	m.triageStates[key] = normalizedState
	m.triageEvents[key] = append(m.triageEvents[key], normalizedEvent)
	return nil
}

// ListFindingTriageEvents returns triage actions newest-first for one finding id.
func (m *MemoryStore) ListFindingTriageEvents(ctx context.Context, findingID string, limit int) ([]FindingTriageEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedID := strings.TrimSpace(findingID)
	if normalizedID == "" {
		return nil, ErrNotFound
	}
	events := append([]FindingTriageEvent(nil), m.triageEvents[findingScopeKey(scope, normalizedID)]...)
	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

// UpsertArtifacts persists raw and normalized scan artifacts idempotently.
func (m *MemoryStore) UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
		return ErrNotFound
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
func (m *MemoryStore) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	records := make([]ScanRecord, 0, len(m.scanIDs))
	for _, scanID := range m.scanIDs {
		record := m.scans[scanID]
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		records = append(records, record)
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
func (m *MemoryStore) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]domain.Finding, 0, len(m.findings))
	for _, finding := range m.findings {
		scan, exists := m.scans[finding.ScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
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

// ListFindingsByScan returns latest findings first for one scan.
func (m *MemoryStore) ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
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
func (m *MemoryStore) ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	filteredScanID := strings.TrimSpace(filter.ScanID)
	if filteredScanID != "" {
		scan, exists := m.scans[filteredScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			return nil, ErrNotFound
		}
	}

	namePrefix := strings.ToLower(strings.TrimSpace(filter.NamePrefix))
	provider := strings.ToLower(strings.TrimSpace(filter.Provider))
	identityType := strings.ToLower(strings.TrimSpace(filter.Type))
	result := []domain.Identity{}
	for key, identity := range m.identities {
		scanID := scanKeyPrefix(key)
		scan, exists := m.scans[scanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			continue
		}
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
func (m *MemoryStore) ListRelationships(ctx context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	filteredScanID := strings.TrimSpace(filter.ScanID)
	if filteredScanID != "" {
		scan, exists := m.scans[filteredScanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			return nil, ErrNotFound
		}
	}
	relType := strings.ToLower(strings.TrimSpace(filter.Type))
	fromNode := strings.TrimSpace(filter.FromNodeID)
	toNode := strings.TrimSpace(filter.ToNodeID)

	result := []domain.Relationship{}
	for key, relationship := range m.relationships {
		scanID := scanKeyPrefix(key)
		scan, exists := m.scans[scanID]
		if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
			continue
		}
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
func (m *MemoryStore) AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
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
func (m *MemoryStore) ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	scan, exists := m.scans[scanID]
	if !exists || !MatchScope(scope, scan.TenantID, scan.WorkspaceID) {
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

func findingScopeKey(scope Scope, findingID string) string {
	normalized := scope.Normalize()
	return normalized.TenantID + "|" + normalized.WorkspaceID + "|" + strings.TrimSpace(findingID)
}

func normalizeFindingTriageStateForWrite(state FindingTriageState) (FindingTriageState, error) {
	normalizedID := strings.TrimSpace(state.FindingID)
	if normalizedID == "" {
		return FindingTriageState{}, fmt.Errorf("finding id is required")
	}
	state.FindingID = normalizedID
	state.Assignee = strings.TrimSpace(state.Assignee)
	state.UpdatedBy = strings.TrimSpace(state.UpdatedBy)
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	} else {
		state.UpdatedAt = state.UpdatedAt.UTC()
	}
	return state, nil
}

func normalizeFindingTriageEventForWrite(event FindingTriageEvent) (FindingTriageEvent, error) {
	normalizedID := strings.TrimSpace(event.FindingID)
	if normalizedID == "" {
		return FindingTriageEvent{}, fmt.Errorf("finding id is required")
	}
	if strings.TrimSpace(event.ID) == "" {
		event.ID = uuid.NewString()
	}
	event.FindingID = normalizedID
	event.Action = strings.TrimSpace(event.Action)
	event.Assignee = strings.TrimSpace(event.Assignee)
	event.Comment = strings.TrimSpace(event.Comment)
	event.Actor = strings.TrimSpace(event.Actor)
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	return event, nil
}

// CreateRepoScan persists one repository exposure scan start event.
func (m *MemoryStore) CreateRepoScan(ctx context.Context, repository string, startedAt time.Time) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	return m.createRepoScanLocked(scope, strings.TrimSpace(repository), "running", 0, 0, startedAt), nil
}

// CreateQueuedRepoScan persists one queued repository exposure scan request.
func (m *MemoryStore) CreateQueuedRepoScan(ctx context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	return m.createRepoScanLocked(scope, strings.TrimSpace(repository), "queued", historyLimit, maxFindings, queuedAt), nil
}

// ClaimNextQueuedRepoScan moves one queued repository scan to running for execution.
func (m *MemoryStore) ClaimNextQueuedRepoScan(ctx context.Context) (RepoScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	var claimed RepoScanRecord
	found := false
	for _, scanID := range m.repoScanIDs {
		record := m.repoScans[scanID]
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
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
func (m *MemoryStore) CountQueuedRepoScans(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, record := range m.repoScans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if record.Status == "queued" {
			count++
		}
	}
	return count, nil
}

// CountPendingRepoScansByRepository returns queued/running scan count for one repository.
func (m *MemoryStore) CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	normalizedRepository := strings.TrimSpace(repository)
	if normalizedRepository == "" {
		return 0, nil
	}
	count := 0
	for _, record := range m.repoScans {
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.Repository), normalizedRepository) {
			continue
		}
		if record.Status == "queued" || record.Status == "running" {
			count++
		}
	}
	return count, nil
}

// RequeueRepoScan moves a running repository scan back to queued state.
func (m *MemoryStore) RequeueRepoScan(ctx context.Context, repoScanID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
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

func (m *MemoryStore) createRepoScanLocked(scope Scope, repository string, status string, historyLimit int, maxFindings int, startedAt time.Time) RepoScanRecord {
	normalizedScope := scope.Normalize()
	record := RepoScanRecord{
		ID:           uuid.NewString(),
		TenantID:     normalizedScope.TenantID,
		WorkspaceID:  normalizedScope.WorkspaceID,
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
func (m *MemoryStore) GetRepoScan(ctx context.Context, repoScanID string) (RepoScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	record, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
		return RepoScanRecord{}, ErrNotFound
	}
	return record, nil
}

// CompleteRepoScan finalizes repo scan metadata.
func (m *MemoryStore) CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	record, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
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
func (m *MemoryStore) UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	repoScan, exists := m.repoScans[repoScanID]
	if !exists || !MatchScope(scope, repoScan.TenantID, repoScan.WorkspaceID) {
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
func (m *MemoryStore) ListRepoScans(ctx context.Context, limit int) ([]RepoScanRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RepoScanRecord, 0, len(m.repoScanIDs))
	for _, scanID := range m.repoScanIDs {
		record := m.repoScans[scanID]
		if !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
		result = append(result, record)
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
func (m *MemoryStore) ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	repoScanID := strings.TrimSpace(filter.RepoScanID)
	if repoScanID != "" {
		record, exists := m.repoScans[repoScanID]
		if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			return nil, ErrNotFound
		}
	}
	severity := strings.ToLower(strings.TrimSpace(filter.Severity))
	findingType := strings.ToLower(strings.TrimSpace(filter.Type))

	result := make([]domain.Finding, 0, len(m.repoFindings))
	for _, finding := range m.repoFindings {
		record, exists := m.repoScans[finding.ScanID]
		if !exists || !MatchScope(scope, record.TenantID, record.WorkspaceID) {
			continue
		}
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

// UpsertRBACRole creates or updates one workspace-scoped role.
func (m *MemoryStore) UpsertRBACRole(ctx context.Context, role RBACRole) (RBACRole, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RBACRole{}, err
	}

	name := strings.ToLower(strings.TrimSpace(role.Name))
	if name == "" {
		return RBACRole{}, fmt.Errorf("role name is required")
	}
	roleKey := rbacRoleNameScopeKey(scope, name)
	existingID, exists := m.rbacRoleByName[roleKey]

	now := time.Now().UTC()
	normalized := RBACRole{
		ID:          strings.TrimSpace(role.ID),
		TenantID:    scope.Normalize().TenantID,
		WorkspaceID: scope.Normalize().WorkspaceID,
		Name:        name,
		Description: strings.TrimSpace(role.Description),
		IsBuiltIn:   role.IsBuiltIn,
		Permissions: normalizeRBACPermissionList(role.Permissions),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if exists {
		existingRole := m.rbacRoles[existingID]
		normalized.ID = existingRole.ID
		normalized.CreatedAt = existingRole.CreatedAt
		normalized.UpdatedAt = now
		if existingRole.IsBuiltIn {
			normalized.IsBuiltIn = true
		}
	} else if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	}

	m.rbacRoles[normalized.ID] = normalized
	m.rbacRoleByName[roleKey] = normalized.ID
	m.rbacRolePerms[normalized.ID] = append([]string(nil), normalized.Permissions...)
	return normalized, nil
}

// ListRBACRoles returns roles for current tenant/workspace scope.
func (m *MemoryStore) ListRBACRoles(ctx context.Context) ([]RBACRole, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}

	normalizedScope := scope.Normalize()
	roles := []RBACRole{}
	for _, role := range m.rbacRoles {
		if !MatchScope(normalizedScope, role.TenantID, role.WorkspaceID) {
			continue
		}
		roleCopy := role
		roleCopy.Permissions = append([]string(nil), m.rbacRolePerms[role.ID]...)
		roles = append(roles, roleCopy)
	}
	sort.SliceStable(roles, func(i, j int) bool {
		if roles[i].Name == roles[j].Name {
			return roles[i].ID < roles[j].ID
		}
		return roles[i].Name < roles[j].Name
	})
	return roles, nil
}

// DeleteRBACRole removes one role and any associated bindings.
func (m *MemoryStore) DeleteRBACRole(ctx context.Context, roleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalizedRoleID := strings.TrimSpace(roleID)
	if normalizedRoleID == "" {
		return ErrNotFound
	}
	role, exists := m.rbacRoles[normalizedRoleID]
	if !exists || !MatchScope(scope, role.TenantID, role.WorkspaceID) {
		return ErrNotFound
	}
	if role.IsBuiltIn {
		return fmt.Errorf("built-in roles cannot be deleted")
	}
	delete(m.rbacRoles, normalizedRoleID)
	delete(m.rbacRolePerms, normalizedRoleID)
	delete(m.rbacRoleByName, rbacRoleNameScopeKey(scope, role.Name))
	for bindingID, binding := range m.rbacBindings {
		if binding.RoleID == normalizedRoleID && MatchScope(scope, binding.TenantID, binding.WorkspaceID) {
			delete(m.rbacBindings, bindingID)
		}
	}
	return nil
}

// UpsertRBACBinding binds one subject to one role inside current scope.
func (m *MemoryStore) UpsertRBACBinding(ctx context.Context, binding RBACBinding) (RBACBinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return RBACBinding{}, err
	}
	normalizedScope := scope.Normalize()

	subjectType, err := normalizeRBACSubjectType(binding.SubjectType)
	if err != nil {
		return RBACBinding{}, err
	}
	subjectID := strings.TrimSpace(binding.SubjectID)
	if subjectID == "" {
		return RBACBinding{}, fmt.Errorf("subject id is required")
	}
	roleID := strings.TrimSpace(binding.RoleID)
	if roleID == "" {
		return RBACBinding{}, fmt.Errorf("role id is required")
	}
	role, exists := m.rbacRoles[roleID]
	if !exists || !MatchScope(normalizedScope, role.TenantID, role.WorkspaceID) {
		return RBACBinding{}, ErrNotFound
	}

	for _, existing := range m.rbacBindings {
		if !MatchScope(normalizedScope, existing.TenantID, existing.WorkspaceID) {
			continue
		}
		if existing.SubjectType == subjectType &&
			existing.SubjectID == subjectID &&
			existing.RoleID == roleID {
			updated := existing
			if binding.ExpiresAt != nil {
				expires := binding.ExpiresAt.UTC()
				updated.ExpiresAt = &expires
			} else {
				updated.ExpiresAt = nil
			}
			m.rbacBindings[updated.ID] = updated
			return updated, nil
		}
	}

	now := time.Now().UTC()
	created := RBACBinding{
		ID:          uuid.NewString(),
		TenantID:    normalizedScope.TenantID,
		WorkspaceID: normalizedScope.WorkspaceID,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		RoleID:      roleID,
		CreatedAt:   now,
	}
	if binding.ExpiresAt != nil {
		expires := binding.ExpiresAt.UTC()
		created.ExpiresAt = &expires
	}
	m.rbacBindings[created.ID] = created
	m.rbacBindingByID = append(m.rbacBindingByID, created.ID)
	return created, nil
}

// ListRBACBindings returns bindings for current tenant/workspace scope.
func (m *MemoryStore) ListRBACBindings(ctx context.Context) ([]RBACBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}

	result := []RBACBinding{}
	for _, bindingID := range m.rbacBindingByID {
		binding, exists := m.rbacBindings[bindingID]
		if !exists {
			continue
		}
		if !MatchScope(scope, binding.TenantID, binding.WorkspaceID) {
			continue
		}
		result = append(result, binding)
	}
	return result, nil
}

// DeleteRBACBinding removes one binding by id in current scope.
func (m *MemoryStore) DeleteRBACBinding(ctx context.Context, bindingID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalizedID := strings.TrimSpace(bindingID)
	if normalizedID == "" {
		return ErrNotFound
	}
	binding, exists := m.rbacBindings[normalizedID]
	if !exists || !MatchScope(scope, binding.TenantID, binding.WorkspaceID) {
		return ErrNotFound
	}
	delete(m.rbacBindings, normalizedID)
	return nil
}

// ListRBACPermissionsForSubject resolves role permissions for one subject in current scope.
func (m *MemoryStore) ListRBACPermissionsForSubject(ctx context.Context, subjectType string, subjectID string, asOf time.Time) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedType, err := normalizeRBACSubjectType(subjectType)
	if err != nil {
		return nil, err
	}
	normalizedSubjectID := strings.TrimSpace(subjectID)
	if normalizedSubjectID == "" {
		return nil, nil
	}

	now := asOf.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	permissions := map[string]struct{}{}
	for _, binding := range m.rbacBindings {
		if !MatchScope(scope, binding.TenantID, binding.WorkspaceID) {
			continue
		}
		if binding.SubjectType != normalizedType || binding.SubjectID != normalizedSubjectID {
			continue
		}
		if binding.ExpiresAt != nil && binding.ExpiresAt.UTC().Before(now) {
			continue
		}
		for _, permission := range m.rbacRolePerms[binding.RoleID] {
			permissions[permission] = struct{}{}
		}
	}
	result := make([]string, 0, len(permissions))
	for permission := range permissions {
		result = append(result, permission)
	}
	sort.Strings(result)
	return result, nil
}

func rbacRoleNameScopeKey(scope Scope, name string) string {
	normalized := scope.Normalize()
	return normalized.TenantID + "|" + normalized.WorkspaceID + "|" + strings.ToLower(strings.TrimSpace(name))
}

// Close closes store resources.
func (m *MemoryStore) Close() error {
	return nil
}
