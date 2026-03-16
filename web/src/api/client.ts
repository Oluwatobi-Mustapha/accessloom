export type FindingsSummary = {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
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

export const apiClient = {
  getFindingsSummary(apiKey?: string) {
    return request<FindingsSummary>('/v1/findings/summary', apiKey);
  },
  getFindingsTrends(apiKey?: string) {
    return request<{ items: Array<{ scan_id: string; started_at: string; total: number }> }>('/v1/findings/trends', apiKey);
  },
  listScans(apiKey?: string) {
    return request<{ items: Array<{ id: string; started_at: string; status: string; finding_count: number }> }>('/v1/scans', apiKey);
  }
};
