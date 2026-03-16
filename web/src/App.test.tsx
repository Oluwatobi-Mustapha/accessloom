import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';

function ok(payload: unknown) {
  return Promise.resolve({
    ok: true,
    json: async () => payload
  });
}

describe('App', () => {
  it('renders summary and explorer data from API', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v1/findings/summary')) {
        return ok({ total: 2, by_severity: { high: 1, medium: 1 }, by_type: { risky_trust_policy: 1, ownerless_identity: 1 } });
      }
      if (url.includes('/v1/findings/trends')) {
        return ok({ items: [{ scan_id: 'scan-1', started_at: '2026-03-16T00:00:00Z', total: 2, by_severity: { high: 1, medium: 1 } }] });
      }
      if (url.endsWith('/v1/scans')) {
        return ok({ items: [{ id: 'scan-1', provider: 'aws', status: 'completed', started_at: '2026-03-16T00:00:00Z', asset_count: 3, finding_count: 2 }] });
      }
      if (url.includes('/v1/findings?')) {
        return ok({
          items: [
            {
              id: 'f-1',
              scan_id: 'scan-1',
              type: 'risky_trust_policy',
              severity: 'high',
              title: 'Risky trust',
              human_summary: 'summary',
              remediation: 'fix',
              created_at: '2026-03-16T00:00:00Z'
            }
          ]
        });
      }
      if (url.includes('/v1/findings/f-1')) {
        return ok({
          id: 'f-1',
          scan_id: 'scan-1',
          type: 'risky_trust_policy',
          severity: 'high',
          title: 'Risky trust',
          human_summary: 'summary',
          remediation: 'fix',
          created_at: '2026-03-16T00:00:00Z'
        });
      }
      if (url.includes('/v1/scans/scan-1/diff')) {
        return ok({
          scan_id: 'scan-1',
          added_count: 1,
          resolved_count: 0,
          persisting_count: 1,
          added: [],
          resolved: [],
          persisting: []
        });
      }
      if (url.includes('/v1/identities')) {
        return ok({
          items: [
            {
              id: 'i-1',
              provider: 'aws',
              type: 'role',
              name: 'payments-app',
              arn: 'arn:aws:iam::123456789012:role/payments-app',
              owner_hint: 'team-security',
              created_at: '2026-03-16T00:00:00Z',
              raw_ref: 'raw-1'
            }
          ]
        });
      }
      if (url.includes('/v1/relationships')) {
        return ok({
          items: [
            {
              id: 'r-1',
              type: 'can_assume',
              from_node_id: 'a',
              to_node_id: 'b',
              evidence_ref: 'e',
              discovered_at: '2026-03-16T00:00:00Z'
            }
          ]
        });
      }
      if (url.includes('/v1/scans/scan-1/events')) {
        return ok({
          items: [{ id: 'e-1', scan_id: 'scan-1', level: 'info', message: 'scan completed', created_at: '2026-03-16T00:00:00Z' }]
        });
      }
      return Promise.resolve({ ok: false, status: 404, json: async () => ({ error: 'not found' }) });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('Total Findings: 2')).toBeInTheDocument();
      expect(screen.getByText('Added: 1')).toBeInTheDocument();
      expect(screen.getByText('Identities: 1')).toBeInTheDocument();
      expect(screen.getByText('Risky trust')).toBeInTheDocument();
    });
  });
});
