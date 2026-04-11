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
  triage?: FindingTriage;
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

export type RequestAuthContext = {
  apiKey?: string;
  tenantID?: string;
  workspaceID?: string;
  bearerToken?: string;
};

export type FindingLifecycleStatus = 'open' | 'ack' | 'suppressed' | 'resolved';

export type FindingTriage = {
  status: FindingLifecycleStatus;
  assignee?: string;
  suppression_expires_at?: string;
  updated_at?: string;
  updated_by?: string;
};

export type FindingTriageEvent = {
  id: string;
  finding_id: string;
  action: string;
  from_status: FindingLifecycleStatus;
  to_status: FindingLifecycleStatus;
  assignee?: string;
  suppression_expires_at?: string;
  comment?: string;
  actor?: string;
  created_at: string;
};

export type FindingTriageRequest = {
  status?: FindingLifecycleStatus;
  assignee?: string;
  suppression_expires_at?: string;
  comment?: string;
};

const configuredURL = import.meta.env.VITE_IDENTRAIL_API_URL as string | undefined;
if (import.meta.env.PROD) {
  if (!configuredURL) {
    throw new Error('VITE_IDENTRAIL_API_URL must be set in production builds');
  }
  const parsed = new URL(configuredURL);
  if (parsed.protocol === 'http:' && parsed.hostname !== 'localhost') {
    throw new Error('VITE_IDENTRAIL_API_URL must use HTTPS in production (HTTP only allowed for localhost)');
  }
}
const baseURL = configuredURL ?? 'http://localhost:8080';

function trimOrUndefined(value?: string): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function buildRequestHeaders(auth?: RequestAuthContext): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const apiKey = trimOrUndefined(auth?.apiKey);
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }
  const tenantID = trimOrUndefined(auth?.tenantID);
  if (tenantID) {
    headers['X-Identrail-Tenant-ID'] = tenantID;
  }
  const workspaceID = trimOrUndefined(auth?.workspaceID);
  if (workspaceID) {
    headers['X-Identrail-Workspace-ID'] = workspaceID;
  }
  const bearerToken = trimOrUndefined(auth?.bearerToken);
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  }
  return headers;
}

export function mergeRequestHeaders(auth?: RequestAuthContext, initHeaders?: HeadersInit): Headers {
  const headers = new Headers(buildRequestHeaders(auth));
  if (!initHeaders) {
    return headers;
  }
  const normalizedHeaders = new Headers(initHeaders);
  normalizedHeaders.forEach((value, key) => {
    headers.set(key, value);
  });
  return headers;
}

async function request<T>(path: string, auth?: RequestAuthContext, init: RequestInit = {}): Promise<T> {
  const headers = mergeRequestHeaders(auth, init.headers);
  const res = await fetch(`${baseURL}${path}`, { ...init, headers });
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const payload = (await res.json()) as { error?: string };
      if (payload?.error) {
        message = payload.error;
      }
    } catch {
      // Keep status-based message when server does not return a JSON error body.
    }
    throw new Error(message);
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
  getFindingsSummary(auth?: RequestAuthContext) {
    return request<FindingsSummary>('/v1/findings/summary', auth);
  },
  getFindingsTrends(
    filters: { points?: number; severity?: string; type?: string } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: TrendPoint[] }>(`/v1/findings/trends${buildQuery(filters)}`, auth);
  },
  listScans(auth?: RequestAuthContext) {
    return request<{ items: ScanRecord[] }>('/v1/scans?sort_by=started_at&sort_order=desc', auth);
  },
  listFindings(
    filters: {
      limit?: number;
      scan_id?: string;
      severity?: string;
      type?: string;
      sort_by?: string;
      sort_order?: 'asc' | 'desc';
    } = {},
    auth?: RequestAuthContext
  ) {
    return request<{ items: Finding[] }>(`/v1/findings${buildQuery(filters)}`, auth);
  },
  getFinding(findingID: string, scanID?: string, auth?: RequestAuthContext) {
    const suffix = buildQuery({ scan_id: scanID });
    return request<Finding>(`/v1/findings/${encodeURIComponent(findingID)}${suffix}`, auth);
  },
  listFindingHistory(findingID: string, scanID?: string, limit = 20, auth?: RequestAuthContext) {
    return request<{ items: FindingTriageEvent[] }>(
      `/v1/findings/${encodeURIComponent(findingID)}/history${buildQuery({ scan_id: scanID, limit })}`,
      auth
    );
  },
  triageFinding(findingID: string, payload: FindingTriageRequest, scanID?: string, auth?: RequestAuthContext) {
    const suffix = buildQuery({ scan_id: scanID });
    return request<{ finding: Finding }>(`/v1/findings/${encodeURIComponent(findingID)}/triage${suffix}`, auth, {
      method: 'PATCH',
      body: JSON.stringify(payload)
    });
  },
  getScanDiff(scanID: string, limit = 20, auth?: RequestAuthContext, previousScanID?: string) {
    return request<ScanDiff>(
      `/v1/scans/${encodeURIComponent(scanID)}/diff${buildQuery({
        limit,
        previous_scan_id: previousScanID
      })}`,
      auth
    );
  },
  listIdentities(scanID: string, limit = 100, auth?: RequestAuthContext) {
    return request<{ items: Identity[] }>(
      `/v1/identities${buildQuery({ scan_id: scanID, limit, sort_by: 'name', sort_order: 'asc' })}`,
      auth
    );
  },
  listRelationships(scanID: string, limit = 100, auth?: RequestAuthContext) {
    return request<{ items: Relationship[] }>(
      `/v1/relationships${buildQuery({ scan_id: scanID, limit, sort_by: 'discovered_at', sort_order: 'desc' })}`,
      auth
    );
  },
  listScanEvents(scanID: string, level?: string, limit = 50, auth?: RequestAuthContext) {
    return request<{ items: ScanEvent[] }>(
      `/v1/scans/${encodeURIComponent(scanID)}/events${buildQuery({
        level,
        limit,
        sort_by: 'created_at',
        sort_order: 'desc'
      })}`,
      auth
    );
  }
};

export { buildQuery };
