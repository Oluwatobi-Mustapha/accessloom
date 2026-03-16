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

    await apiClient.listFindings({ scan_id: 'scan-1', severity: 'high', type: 'risky_trust_policy' }, 'reader');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain('/v1/findings?scan_id=scan-1&severity=high&type=risky_trust_policy');
    expect(options.headers).toMatchObject({
      'Content-Type': 'application/json',
      'X-API-Key': 'reader'
    });
  });

  it('encodes scan id for diff URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getScanDiff('scan/id with space', 20, 'reader');
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans/scan%2Fid%20with%20space/diff?limit=20');
  });

  it('adds baseline scan query when provided', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({})
    });
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.getScanDiff('scan-2', 20, 'reader', 'scan-1');
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toContain('/v1/scans/scan-2/diff?limit=20&previous_scan_id=scan-1');
  });
});
