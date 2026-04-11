import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
      if (url.includes('/v1/scans?')) {
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
      if (url.includes('/v1/findings/f-1/history')) {
        return ok({
          items: [
            {
              id: 'evt-1',
              finding_id: 'f-1',
              action: 'commented',
              from_status: 'open',
              to_status: 'open',
              comment: 'initial review',
              actor: 'subject:reviewer',
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

  it('shows empty states when no scan data exists', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v1/findings/summary')) return ok({ total: 0, by_severity: {}, by_type: {} });
      if (url.includes('/v1/findings/trends')) return ok({ items: [] });
      if (url.includes('/v1/scans?')) return ok({ items: [] });
      return ok({ items: [] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('Total Findings: 0')).toBeInTheDocument();
      expect(screen.getByText('No scans yet. Trigger a scan from API or CLI.')).toBeInTheDocument();
      expect(screen.getByText('No trend data yet.')).toBeInTheDocument();
    });
  });

  it('shows API error message from backend envelope', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v1/findings/summary')) {
        return Promise.resolve({
          ok: false,
          status: 401,
          json: async () => ({ error: 'unauthorized' })
        });
      }
      if (url.includes('/v1/findings/trends')) return ok({ items: [] });
      if (url.includes('/v1/scans?')) return ok({ items: [] });
      return ok({ items: [] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('unauthorized')).toBeInTheDocument();
    });
  });

  it('applies tenant and workspace headers from dashboard controls', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v1/findings/summary')) return ok({ total: 0, by_severity: {}, by_type: {} });
      if (url.includes('/v1/findings/trends')) return ok({ items: [] });
      if (url.includes('/v1/scans?')) {
        return ok({
          items: [{ id: 'scan-1', provider: 'aws', status: 'completed', started_at: '2026-03-16T00:00:00Z', asset_count: 0, finding_count: 0 }]
        });
      }
      if (url.includes('/v1/findings?')) return ok({ items: [] });
      if (url.includes('/v1/scans/scan-1/diff')) {
        return ok({
          scan_id: 'scan-1',
          added_count: 0,
          resolved_count: 0,
          persisting_count: 0,
          added: [],
          resolved: [],
          persisting: []
        });
      }
      if (url.includes('/v1/identities')) return ok({ items: [] });
      if (url.includes('/v1/relationships')) return ok({ items: [] });
      if (url.includes('/v1/scans/scan-1/events')) return ok({ items: [] });
      return ok({ items: [] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    fireEvent.change(screen.getByLabelText('API Key'), { target: { value: 'reader-key' } });
    fireEvent.change(screen.getByLabelText('Tenant ID'), { target: { value: 'tenant-a' } });
    fireEvent.change(screen.getByLabelText('Workspace ID'), { target: { value: 'workspace-a' } });

    await waitFor(() => {
      const matchedCall = fetchMock.mock.calls.find((call) => {
        const requestCall = call as unknown as [RequestInfo | URL, RequestInit?];
        const options = requestCall[1];
        if (!options?.headers) return false;
        const headers = new Headers(options.headers);
        return (
          headers.get('x-api-key') === 'reader-key' &&
          headers.get('x-identrail-tenant-id') === 'tenant-a' &&
          headers.get('x-identrail-workspace-id') === 'workspace-a'
        );
      });
      expect(matchedCall).toBeDefined();
    });
  });

  it('supports finding triage actions and renders audit trail', async () => {
    let historyItems = [
      {
        id: 'evt-1',
        finding_id: 'f-1',
        action: 'commented',
        from_status: 'open',
        to_status: 'open',
        comment: 'initial review',
        actor: 'subject:reviewer',
        created_at: '2026-03-16T00:00:00Z'
      }
    ];

    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/v1/findings/summary')) return ok({ total: 1, by_severity: { high: 1 }, by_type: { risky_trust_policy: 1 } });
      if (url.includes('/v1/findings/trends')) return ok({ items: [] });
      if (url.includes('/v1/scans?')) {
        return ok({
          items: [{ id: 'scan-1', provider: 'aws', status: 'completed', started_at: '2026-03-16T00:00:00Z', asset_count: 1, finding_count: 1 }]
        });
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
              created_at: '2026-03-16T00:00:00Z',
              triage: { status: 'open' }
            }
          ]
        });
      }
      if (url.includes('/v1/findings/f-1/history')) {
        return ok({ items: historyItems });
      }
      if (url.includes('/v1/findings/f-1/triage')) {
        historyItems = [
          {
            id: 'evt-2',
            finding_id: 'f-1',
            action: 'acknowledged',
            from_status: 'open',
            to_status: 'ack',
            comment: 'accepted for follow-up',
            actor: 'subject:writer',
            created_at: '2026-03-16T00:01:00Z'
          },
          ...historyItems
        ];
        return ok({
          finding: {
            id: 'f-1',
            scan_id: 'scan-1',
            type: 'risky_trust_policy',
            severity: 'high',
            title: 'Risky trust',
            human_summary: 'summary',
            remediation: 'fix',
            created_at: '2026-03-16T00:00:00Z',
            triage: { status: 'ack', assignee: 'platform' }
          }
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
          created_at: '2026-03-16T00:00:00Z',
          triage: { status: 'open' }
        });
      }
      if (url.includes('/v1/scans/scan-1/diff')) {
        return ok({
          scan_id: 'scan-1',
          added_count: 0,
          resolved_count: 0,
          persisting_count: 1,
          added: [],
          resolved: [],
          persisting: []
        });
      }
      if (url.includes('/v1/identities')) return ok({ items: [] });
      if (url.includes('/v1/relationships')) return ok({ items: [] });
      if (url.includes('/v1/scans/scan-1/events')) return ok({ items: [] });
      return ok({ items: [] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    await waitFor(() => {
      expect(screen.getAllByText('Risky trust').length).toBeGreaterThan(0);
      expect(screen.getByText('commented')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText('Assignee'), { target: { value: 'platform' } });
    fireEvent.change(screen.getByLabelText('Comment'), { target: { value: 'accepted for follow-up' } });
    fireEvent.click(screen.getByRole('button', { name: 'Ack' }));

    await waitFor(() => {
      expect(
        screen.getByText((_, node) => {
          const text = node?.textContent?.replace(/\s+/g, ' ').trim();
          return text === 'Status: ack';
        })
      ).toBeInTheDocument();
      expect(screen.getByText('acknowledged')).toBeInTheDocument();
    });

    const patchCall = fetchMock.mock.calls.find((call) => {
      const requestCall = call as unknown as [RequestInfo | URL, RequestInit?];
      return String(requestCall[0]).includes('/v1/findings/f-1/triage?scan_id=scan-1');
    }) as [RequestInfo | URL, RequestInit] | undefined;
    expect(patchCall).toBeDefined();
    expect(patchCall?.[1].method).toBe('PATCH');
  });

  it('keeps finding detail visible when history fetch fails', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v1/findings/summary')) return ok({ total: 1, by_severity: { high: 1 }, by_type: { risky_trust_policy: 1 } });
      if (url.includes('/v1/findings/trends')) return ok({ items: [] });
      if (url.includes('/v1/scans?')) {
        return ok({
          items: [{ id: 'scan-1', provider: 'aws', status: 'completed', started_at: '2026-03-16T00:00:00Z', asset_count: 1, finding_count: 1 }]
        });
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
              created_at: '2026-03-16T00:00:00Z',
              triage: { status: 'open' }
            }
          ]
        });
      }
      if (url.includes('/v1/findings/f-1/history')) {
        return Promise.resolve({
          ok: false,
          status: 500,
          json: async () => ({ error: 'history unavailable' })
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
          created_at: '2026-03-16T00:00:00Z',
          triage: { status: 'open' }
        });
      }
      if (url.includes('/v1/scans/scan-1/diff')) {
        return ok({
          scan_id: 'scan-1',
          added_count: 0,
          resolved_count: 0,
          persisting_count: 1,
          added: [],
          resolved: [],
          persisting: []
        });
      }
      if (url.includes('/v1/identities')) return ok({ items: [] });
      if (url.includes('/v1/relationships')) return ok({ items: [] });
      if (url.includes('/v1/scans/scan-1/events')) return ok({ items: [] });
      return ok({ items: [] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    await waitFor(() => {
      expect(screen.getAllByText('Risky trust').length).toBeGreaterThan(0);
      expect(screen.getByText('summary')).toBeInTheDocument();
      expect(screen.getByText('history unavailable')).toBeInTheDocument();
    });
  });
});
