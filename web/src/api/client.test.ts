import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient, buildQuery } from './client';

describe('buildQuery', () => {
  it('encodes defined query params only', () => {
    const query = buildQuery({ scan_id: 'scan-1', severity: 'high', empty: '', missing: undefined });
    expect(query).toBe('?scan_id=scan-1&severity=high');
  });
});

describe('apiClient', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('builds findings URL with filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listFindings(
      { scan_id: 'scan-1', severity: 'high', type: 'risky_trust_policy' },
      { apiKey: 'reader' }
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/findings?scan_id=scan-1&severity=high&type=risky_trust_policy');
    expect(options.headers).toMatchObject({
      'Content-Type': 'application/json',
      'X-API-Key': 'reader'
    });
  });

  it('uses default scan listing sort contract', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listScans({ apiKey: 'reader' });
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans?sort_by=started_at&sort_order=desc');
  });

  it('encodes scan id for diff URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getScanDiff('scan/id with space', 20, { apiKey: 'reader' });
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans/scan%2Fid%20with%20space/diff?limit=20');
  });

  it('adds baseline scan query when provided', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getScanDiff('scan-2', 20, { apiKey: 'reader' }, 'scan-1');
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans/scan-2/diff?limit=20&previous_scan_id=scan-1');
  });

  it('sends enterprise tenant/workspace scope headers when configured', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listScans({
      apiKey: ' reader ',
      tenantID: ' tenant-a ',
      workspaceID: ' workspace-a '
    });

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(options.headers).toMatchObject({
      'X-API-Key': 'reader',
      'X-Identrail-Tenant-ID': 'tenant-a',
      'X-Identrail-Workspace-ID': 'workspace-a'
    });
  });

  it('surfaces backend error envelope message', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'unauthorized' })
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiClient.getFindingsSummary({ apiKey: 'reader' })).rejects.toThrow('unauthorized');
  });

  it('requests finding triage history with scan scope', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [] })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.listFindingHistory('finding-1', 'scan-1', 15, { apiKey: 'reader' });

    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/findings/finding-1/history?scan_id=scan-1&limit=15');
  });

  it('sends triage patch payload for finding workflow actions', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ finding: { id: 'finding-1' } })
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.triageFinding(
      'finding-1',
      { status: 'ack', assignee: 'platform', comment: 'acknowledged' },
      'scan-1',
      { apiKey: 'writer' }
    );

    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/findings/finding-1/triage?scan_id=scan-1');
    expect(options.method).toBe('PATCH');
    expect(options.body).toBe(JSON.stringify({ status: 'ack', assignee: 'platform', comment: 'acknowledged' }));
  });
});
