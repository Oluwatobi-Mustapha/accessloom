export type FindingsSummary = {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
};

export type Finding = {
  id: string;
  scan_id: string;
  type: string;
  severity: string;
  title: string;
  human_summary: string;
  path?: string[];
  evidence?: Record<string, unknown>;
  remediation: string;
  created_at: string;
};

export type ScanRecord = {
  id: string;
  provider: string;
  status: string;
  started_at: string;
  finished_at?: string;
  asset_count: number;
  finding_count: number;
  error_message?: string;
};

export type TrendPoint = {
  scan_id: string;
  started_at: string;
  total: number;
  by_severity: Record<string, number>;
};

export type ScanDiff = {
  scan_id: string;
  previous_scan_id?: string;
  added_count: number;
  resolved_count: number;
  persisting_count: number;
  added: Finding[];
  resolved: Finding[];
  persisting: Finding[];
};

export type Identity = {
  id: string;
  provider: string;
  type: string;
  name: string;
  arn: string;
  owner_hint: string;
  created_at: string;
  last_used_at?: string;
  tags?: Record<string, string>;
  raw_ref: string;
};

export type Relationship = {
  id: string;
  type: string;
  from_node_id: string;
  to_node_id: string;
  evidence_ref: string;
  discovered_at: string;
};

export type ScanEvent = {
  id: string;
  scan_id: string;
  level: string;
  message: string;
  metadata?: Record<string, unknown>;
  created_at: string;
};

const baseURL = (import.meta.env.VITE_IDENTRAIL_API_URL as string | undefined) ?? 'http://localhost:8080';

async function request<T>(path: string, apiKey?: string): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }
  const res = await fetch(`${baseURL}${path}`, { headers });
  if (!res.ok) {
    throw new Error(`Request failed (${res.status})`);
  }
  return (await res.json()) as T;
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === '') return;
    query.set(key, String(value));
  });
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export const apiClient = {
  getFindingsSummary(apiKey?: string) {
    return request<FindingsSummary>('/v1/findings/summary', apiKey);
  },
  getFindingsTrends(
    filters: { points?: number; severity?: string; type?: string } = {},
    apiKey?: string
  ) {
    return request<{ items: TrendPoint[] }>(`/v1/findings/trends${buildQuery(filters)}`, apiKey);
  },
  listScans(apiKey?: string) {
    return request<{ items: ScanRecord[] }>('/v1/scans', apiKey);
  },
  listFindings(
    filters: { limit?: number; scan_id?: string; severity?: string; type?: string } = {},
    apiKey?: string
  ) {
    return request<{ items: Finding[] }>(`/v1/findings${buildQuery(filters)}`, apiKey);
  },
  getFinding(findingID: string, scanID?: string, apiKey?: string) {
    const suffix = buildQuery({ scan_id: scanID });
    return request<Finding>(`/v1/findings/${encodeURIComponent(findingID)}${suffix}`, apiKey);
  },
  getScanDiff(scanID: string, limit = 20, apiKey?: string, previousScanID?: string) {
    return request<ScanDiff>(
      `/v1/scans/${encodeURIComponent(scanID)}/diff${buildQuery({
        limit,
        previous_scan_id: previousScanID
      })}`,
      apiKey
    );
  },
  listIdentities(scanID: string, limit = 100, apiKey?: string) {
    return request<{ items: Identity[] }>(
      `/v1/identities${buildQuery({ scan_id: scanID, limit })}`,
      apiKey
    );
  },
  listRelationships(scanID: string, limit = 100, apiKey?: string) {
    return request<{ items: Relationship[] }>(
      `/v1/relationships${buildQuery({ scan_id: scanID, limit })}`,
      apiKey
    );
  },
  listScanEvents(scanID: string, level?: string, limit = 50, apiKey?: string) {
    return request<{ items: ScanEvent[] }>(
      `/v1/scans/${encodeURIComponent(scanID)}/events${buildQuery({ level, limit })}`,
      apiKey
    );
  }
};

export { buildQuery };
