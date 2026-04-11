import { useEffect, useMemo, useState } from 'react';
import {
  apiClient,
  type Finding,
  type FindingLifecycleStatus,
  type FindingTriageEvent,
  type FindingsSummary,
  type Identity,
  type FindingTriageRequest,
  type RequestAuthContext,
  type Relationship,
  type ScanDiff,
  type ScanEvent,
  type ScanRecord,
  type TrendPoint
} from './api/client';

function formatDateTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function toDateTimeLocal(value?: string): string {
  if (!value) {
    return '';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }
  const year = parsed.getFullYear();
  const month = String(parsed.getMonth() + 1).padStart(2, '0');
  const day = String(parsed.getDate()).padStart(2, '0');
  const hour = String(parsed.getHours()).padStart(2, '0');
  const minute = String(parsed.getMinutes()).padStart(2, '0');
  return `${year}-${month}-${day}T${hour}:${minute}`;
}

function fromDateTimeLocal(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const parsed = new Date(trimmed);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
}

function findingStatus(finding: Finding | null): FindingLifecycleStatus {
  return finding?.triage?.status ?? 'open';
}

function formatTriageAction(action: string): string {
  return action.replace(/_/g, ' ');
}

export function App() {
  const [apiKey, setApiKey] = useState('');
  const [tenantID, setTenantID] = useState('');
  const [workspaceID, setWorkspaceID] = useState('');
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingID, setSelectedFindingID] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [scanDiff, setScanDiff] = useState<ScanDiff | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [selectedScanID, setSelectedScanID] = useState('');
  const [baselineScanID, setBaselineScanID] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [detailsError, setDetailsError] = useState<string | null>(null);
  const [findingError, setFindingError] = useState<string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [triageSuccess, setTriageSuccess] = useState<string | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [loadingFinding, setLoadingFinding] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [submittingTriage, setSubmittingTriage] = useState(false);
  const [triageHistory, setTriageHistory] = useState<FindingTriageEvent[]>([]);
  const [triageAssignee, setTriageAssignee] = useState('');
  const [triageSuppressUntil, setTriageSuppressUntil] = useState('');
  const [triageComment, setTriageComment] = useState('');
  const [refreshNonce, setRefreshNonce] = useState(0);

  const topSeverities = useMemo(() => {
    if (!summary) return [] as Array<[string, number]>;
    return Object.entries(summary.by_severity).sort((a, b) => b[1] - a[1]);
  }, [summary]);

  const topTypes = useMemo(() => {
    if (!summary) return [] as Array<[string, number]>;
    return Object.entries(summary.by_type).sort((a, b) => b[1] - a[1]).slice(0, 4);
  }, [summary]);

  const availableScanID = useMemo(() => {
    if (!scans.length) return '';
    if (scans.some((scan) => scan.id === selectedScanID)) return selectedScanID;
    return scans[0].id;
  }, [scans, selectedScanID]);

  const baselineOptions = useMemo(
    () => scans.filter((scan) => scan.id !== availableScanID),
    [scans, availableScanID]
  );

  const requestAuth = useMemo<RequestAuthContext>(
    () => ({
      apiKey,
      tenantID,
      workspaceID
    }),
    [apiKey, tenantID, workspaceID]
  );

  useEffect(() => {
    let active = true;
    setLoadingOverview(true);
    Promise.all([
      apiClient.getFindingsSummary(requestAuth),
      apiClient.getFindingsTrends({ points: 10 }, requestAuth),
      apiClient.listScans(requestAuth)
    ])
      .then(([summaryData, trendData, scanData]) => {
        if (!active) return;
        setSummary(summaryData);
        setTrends(trendData.items);
        setScans(scanData.items);
        if (scanData.items.length > 0 && !scanData.items.some((scan) => scan.id === selectedScanID)) {
          setSelectedScanID(scanData.items[0].id);
        }
        setOverviewError(null);
      })
      .catch((err: Error) => {
        if (!active) return;
        setSummary(null);
        setTrends([]);
        setScans([]);
        setOverviewError(err.message);
      })
      .finally(() => {
        if (active) setLoadingOverview(false);
      });
    return () => {
      active = false;
    };
  }, [requestAuth, refreshNonce, selectedScanID]);

  useEffect(() => {
    if (!baselineScanID) return;
    if (baselineScanID === availableScanID) {
      setBaselineScanID('');
      return;
    }
    if (!baselineOptions.some((scan) => scan.id === baselineScanID)) {
      setBaselineScanID('');
    }
  }, [availableScanID, baselineOptions, baselineScanID]);

  useEffect(() => {
    const scanID = availableScanID;
    if (!scanID) {
      setFindings([]);
      setScanDiff(null);
      setIdentities([]);
      setRelationships([]);
      setEvents([]);
      setSelectedFindingID('');
      setDetailsError(null);
      return;
    }
    let active = true;
    setLoadingDetails(true);
    Promise.all([
      apiClient.listFindings(
        {
          scan_id: scanID,
          severity: severityFilter,
          type: typeFilter,
          limit: 100,
          sort_by: 'severity',
          sort_order: 'desc'
        },
        requestAuth
      ),
      apiClient.getScanDiff(scanID, 20, requestAuth, baselineScanID || undefined),
      apiClient.listIdentities(scanID, 100, requestAuth),
      apiClient.listRelationships(scanID, 100, requestAuth),
      apiClient.listScanEvents(scanID, 'info', 30, requestAuth)
    ])
      .then(([findingsData, diffData, identitiesData, relationshipsData, eventsData]) => {
        if (!active) return;
        setFindings(findingsData.items);
        setScanDiff(diffData);
        setIdentities(identitiesData.items);
        setRelationships(relationshipsData.items);
        setEvents(eventsData.items);
        if (findingsData.items.length > 0) {
          setSelectedFindingID((current) =>
            findingsData.items.some((item) => item.id === current) ? current : findingsData.items[0].id
          );
        } else {
          setSelectedFindingID('');
        }
        setDetailsError(null);
      })
      .catch((err: Error) => {
        if (!active) return;
        setFindings([]);
        setScanDiff(null);
        setIdentities([]);
        setRelationships([]);
        setEvents([]);
        setSelectedFindingID('');
        setDetailsError(err.message);
      })
      .finally(() => {
        if (active) setLoadingDetails(false);
      });
    return () => {
      active = false;
    };
  }, [availableScanID, baselineScanID, severityFilter, typeFilter, requestAuth, refreshNonce]);

  useEffect(() => {
    const scanID = availableScanID;
    if (!selectedFindingID || !scanID) {
      setSelectedFinding(null);
      setTriageHistory([]);
      setFindingError(null);
      setHistoryError(null);
      setLoadingHistory(false);
      return;
    }
    let active = true;
    setLoadingFinding(true);
    setLoadingHistory(true);
    apiClient
      .getFinding(selectedFindingID, scanID, requestAuth)
      .then((item) => {
        if (!active) return;
        setSelectedFinding(item);
        setFindingError(null);
      })
      .catch((err: Error) => {
        if (!active) return;
        setSelectedFinding(null);
        setFindingError(err.message);
      })
      .finally(() => {
        if (!active) return;
        setLoadingFinding(false);
      });

    apiClient
      .listFindingHistory(selectedFindingID, scanID, 20, requestAuth)
      .then((history) => {
        if (!active) return;
        setTriageHistory(history.items);
        setHistoryError(null);
      })
      .catch((err: Error) => {
        if (!active) return;
        setTriageHistory([]);
        setHistoryError(err.message);
      })
      .finally(() => {
        if (!active) return;
        setLoadingHistory(false);
      });
    return () => {
      active = false;
    };
  }, [selectedFindingID, availableScanID, requestAuth]);

  useEffect(() => {
    setTriageAssignee(selectedFinding?.triage?.assignee ?? '');
    setTriageSuppressUntil(toDateTimeLocal(selectedFinding?.triage?.suppression_expires_at));
    setTriageComment('');
    setTriageError(null);
    setTriageSuccess(null);
  }, [selectedFindingID, selectedFinding?.triage?.assignee, selectedFinding?.triage?.suppression_expires_at]);

  const triggerRefresh = () => setRefreshNonce((value) => value + 1);
  const canSubmitTriage = Boolean(selectedFinding && availableScanID);

  const submitTriageAction = async (status: FindingLifecycleStatus): Promise<void> => {
    if (!selectedFindingID || !availableScanID) {
      return;
    }
    setTriageError(null);
    setTriageSuccess(null);

    const payload: FindingTriageRequest = {
      status,
      assignee: triageAssignee.trim(),
      comment: triageComment.trim()
    };

    if (status === 'suppressed') {
      const suppressionExpiry = fromDateTimeLocal(triageSuppressUntil);
      if (!suppressionExpiry) {
        setTriageError('Suppression requires a valid future "Suppress Until" value.');
        return;
      }
      payload.suppression_expires_at = suppressionExpiry;
    }

    setSubmittingTriage(true);
    try {
      const triageResult = await apiClient.triageFinding(selectedFindingID, payload, availableScanID, requestAuth);
      setSelectedFinding(triageResult.finding);
      setFindings((current) =>
        current.map((finding) => (finding.id === triageResult.finding.id ? triageResult.finding : finding))
      );
      const historyResult = await apiClient.listFindingHistory(selectedFindingID, availableScanID, 20, requestAuth);
      setTriageHistory(historyResult.items);
      setTriageSuccess(`Finding updated to ${status}.`);
      setTriageComment('');
    } catch (err) {
      if (err instanceof Error) {
        setTriageError(err.message);
      } else {
        setTriageError('failed to update finding triage');
      }
    } finally {
      setSubmittingTriage(false);
    }
  };

  return (
    <main className="page">
      <section className="hero">
        <h1>Identrail</h1>
        <p>Identity risk map for cloud workloads and trust paths.</p>
      </section>

      <section className="panel controls">
        <div>
          <label htmlFor="api-key">API Key</label>
          <input
            id="api-key"
            type="password"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder="Optional for local dev"
          />
        </div>
        <div>
          <label htmlFor="tenant-id">Tenant ID</label>
          <input
            id="tenant-id"
            value={tenantID}
            onChange={(event) => setTenantID(event.target.value)}
            placeholder="Optional tenant scope"
          />
        </div>
        <div>
          <label htmlFor="workspace-id">Workspace ID</label>
          <input
            id="workspace-id"
            value={workspaceID}
            onChange={(event) => setWorkspaceID(event.target.value)}
            placeholder="Optional workspace scope"
          />
        </div>
        <div>
          <label htmlFor="scan-id">Scan</label>
          <select
            id="scan-id"
            value={availableScanID}
            onChange={(event) => setSelectedScanID(event.target.value)}
            disabled={scans.length === 0}
          >
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {scan.id.slice(0, 8)} · {scan.status} · findings {scan.finding_count}
              </option>
            ))}
          </select>
          {scans.length === 0 && <p className="hint">No scans yet. Trigger a scan from API or CLI.</p>}
        </div>
        <div>
          <label htmlFor="severity-filter">Severity</label>
          <select
            id="severity-filter"
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
          >
            <option value="">all</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </div>
        <div>
          <label htmlFor="baseline-scan">Baseline Scan</label>
          <select
            id="baseline-scan"
            value={baselineScanID}
            onChange={(event) => setBaselineScanID(event.target.value)}
            disabled={baselineOptions.length === 0}
          >
            <option value="">auto previous</option>
            {baselineOptions.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {scan.id.slice(0, 8)} · {scan.status}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="type-filter">Type</label>
          <input
            id="type-filter"
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
            placeholder="e.g. risky_trust_policy"
          />
        </div>
        <button type="button" onClick={triggerRefresh}>
          Refresh
        </button>
      </section>

      <section className="panel summary">
        <h2>Findings Summary</h2>
        {loadingOverview && <p>Loading overview...</p>}
        {overviewError && <p className="error">{overviewError}</p>}
        {!loadingOverview && !overviewError && summary && (
          <>
            <p className="total">Total Findings: {summary.total}</p>
            <ul className="chip-list">
              {topSeverities.map(([severity, count]) => (
                <li key={severity}>
                  <strong>{severity}</strong>: {count}
                </li>
              ))}
            </ul>
            <ul className="chip-list">
              {topTypes.map(([type, count]) => (
                <li key={type}>
                  <strong>{type}</strong>: {count}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section className="panel">
        <h2>Findings</h2>
        {loadingDetails && <p>Loading findings...</p>}
        {detailsError && <p className="error">{detailsError}</p>}
        {!loadingDetails && !detailsError && findings.length === 0 && <p>No findings for this filter set.</p>}
        {!loadingDetails && !detailsError && findings.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Severity</th>
                <th>Triage</th>
                <th>Type</th>
                <th>Title</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr
                  key={finding.id}
                  className={finding.id === selectedFindingID ? 'selected' : ''}
                  onClick={() => setSelectedFindingID(finding.id)}
                >
                  <td>{finding.id.slice(0, 12)}</td>
                  <td>{finding.severity}</td>
                  <td>{finding.triage?.status ?? 'open'}</td>
                  <td>{finding.type}</td>
                  <td>{finding.title}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel grid-two">
        <div>
          <h2>Finding Detail</h2>
          {loadingFinding && <p>Loading detail...</p>}
          {findingError && <p className="error">{findingError}</p>}
          {!loadingFinding && !findingError && selectedFinding && (
            <>
              <p>
                <strong>{selectedFinding.title}</strong>
              </p>
              <p>{selectedFinding.human_summary}</p>
              <p>
                <strong>Remediation:</strong> {selectedFinding.remediation}
              </p>
              <p>
                <strong>Status:</strong> {findingStatus(selectedFinding)}
              </p>
              <p>
                <strong>Assignee:</strong> {selectedFinding.triage?.assignee || 'unassigned'}
              </p>
              {selectedFinding.triage?.suppression_expires_at && (
                <p>
                  <strong>Suppressed Until:</strong> {formatDateTime(selectedFinding.triage.suppression_expires_at)}
                </p>
              )}

              <div className="triage-controls">
                <h3>Triage Actions</h3>
                <label htmlFor="triage-assignee">Assignee</label>
                <input
                  id="triage-assignee"
                  value={triageAssignee}
                  onChange={(event) => setTriageAssignee(event.target.value)}
                  placeholder="e.g. platform-oncall"
                />

                <label htmlFor="triage-suppress-until">Suppress Until</label>
                <input
                  id="triage-suppress-until"
                  type="datetime-local"
                  value={triageSuppressUntil}
                  onChange={(event) => setTriageSuppressUntil(event.target.value)}
                />

                <label htmlFor="triage-comment">Comment</label>
                <textarea
                  id="triage-comment"
                  value={triageComment}
                  onChange={(event) => setTriageComment(event.target.value)}
                  placeholder="Optional audit comment"
                />

                <div className="triage-actions">
                  <button
                    type="button"
                    onClick={() => void submitTriageAction('ack')}
                    disabled={!canSubmitTriage || submittingTriage}
                  >
                    Ack
                  </button>
                  <button
                    type="button"
                    onClick={() => void submitTriageAction('suppressed')}
                    disabled={!canSubmitTriage || submittingTriage}
                  >
                    Suppress
                  </button>
                  <button
                    type="button"
                    onClick={() => void submitTriageAction('resolved')}
                    disabled={!canSubmitTriage || submittingTriage}
                  >
                    Resolve
                  </button>
                </div>
                {triageSuccess && <p className="success">{triageSuccess}</p>}
                {triageError && <p className="error">{triageError}</p>}
              </div>
            </>
          )}
        </div>
        <div>
          <h2>Scan Diff</h2>
          {!scanDiff && <p>No diff data loaded.</p>}
          {scanDiff && (
            <ul className="stats-list">
              <li>Added: {scanDiff.added_count}</li>
              <li>Resolved: {scanDiff.resolved_count}</li>
              <li>Persisting: {scanDiff.persisting_count}</li>
            </ul>
          )}

          <h3>Triage Audit Trail</h3>
          {loadingHistory && <p>Loading triage history...</p>}
          {historyError && <p className="error">{historyError}</p>}
          {!loadingHistory && !historyError && triageHistory.length === 0 && (
            <p className="hint">No triage actions recorded yet.</p>
          )}
          {!loadingHistory && !historyError && triageHistory.length > 0 && (
            <ul className="stats-list triage-history">
              {triageHistory.map((event) => (
                <li key={event.id}>
                  <strong>{formatTriageAction(event.action)}</strong> · {event.from_status} → {event.to_status} ·{' '}
                  {formatDateTime(event.created_at)}
                  {event.actor && <span> · {event.actor}</span>}
                  {event.comment && <div>{event.comment}</div>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="panel grid-two">
        <div>
          <h2>Explorer Snapshot</h2>
          <ul className="stats-list">
            <li>Identities: {identities.length}</li>
            <li>Relationships: {relationships.length}</li>
            <li>Info Events: {events.length}</li>
          </ul>
          {!loadingDetails && !detailsError && identities.length === 0 && relationships.length === 0 && (
            <p className="hint">No explorer graph data for this scan and filter set.</p>
          )}
        </div>
        <div>
          <h2>Recent Trends</h2>
          {trends.length === 0 ? (
            <p className="hint">No trend data yet.</p>
          ) : (
            <ul className="stats-list">
              {trends.slice(-5).map((point) => (
                <li key={point.scan_id}>
                  {point.scan_id.slice(0, 8)}: {point.total}
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>
    </main>
  );
}
