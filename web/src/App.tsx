import { useEffect, useMemo, useState } from 'react';
import {
  apiClient,
  type Finding,
  type FindingsSummary,
  type Identity,
  type Relationship,
  type ScanDiff,
  type ScanEvent,
  type ScanRecord,
  type TrendPoint
} from './api/client';

export function App() {
  const [apiKey, setApiKey] = useState('');
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
  const [loadingOverview, setLoadingOverview] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [loadingFinding, setLoadingFinding] = useState(false);
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

  useEffect(() => {
    let active = true;
    setLoadingOverview(true);
    Promise.all([
      apiClient.getFindingsSummary(apiKey || undefined),
      apiClient.getFindingsTrends({ points: 10 }, apiKey || undefined),
      apiClient.listScans(apiKey || undefined)
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
  }, [apiKey, refreshNonce, selectedScanID]);

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
        { scan_id: scanID, severity: severityFilter, type: typeFilter, limit: 100 },
        apiKey || undefined
      ),
      apiClient.getScanDiff(scanID, 20, apiKey || undefined, baselineScanID || undefined),
      apiClient.listIdentities(scanID, 100, apiKey || undefined),
      apiClient.listRelationships(scanID, 100, apiKey || undefined),
      apiClient.listScanEvents(scanID, 'info', 30, apiKey || undefined)
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
  }, [availableScanID, baselineScanID, severityFilter, typeFilter, apiKey, refreshNonce]);

  useEffect(() => {
    const scanID = availableScanID;
    if (!selectedFindingID || !scanID) {
      setSelectedFinding(null);
      setFindingError(null);
      return;
    }
    let active = true;
    setLoadingFinding(true);
    apiClient
      .getFinding(selectedFindingID, scanID, apiKey || undefined)
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
        if (active) setLoadingFinding(false);
      });
    return () => {
      active = false;
    };
  }, [selectedFindingID, availableScanID, apiKey]);

  const triggerRefresh = () => setRefreshNonce((value) => value + 1);

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
        </div>
        <div>
          <h2>Recent Trends</h2>
          <ul className="stats-list">
            {trends.slice(-5).map((point) => (
              <li key={point.scan_id}>
                {point.scan_id.slice(0, 8)}: {point.total}
              </li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
