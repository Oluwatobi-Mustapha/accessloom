import { useEffect, useMemo, useState } from 'react';
import { apiClient, type FindingsSummary } from './api/client';

export function App() {
  const [apiKey, setApiKey] = useState('');
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const topSeverities = useMemo(() => {
    if (!summary) return [] as Array<[string, number]>;
    return Object.entries(summary.by_severity).sort((a, b) => b[1] - a[1]);
  }, [summary]);

  useEffect(() => {
    setLoading(true);
    apiClient
      .getFindingsSummary(apiKey || undefined)
      .then((data) => {
        setSummary(data);
        setError(null);
      })
      .catch((err: Error) => {
        setSummary(null);
        setError(err.message);
      })
      .finally(() => setLoading(false));
  }, [apiKey]);

  return (
    <main className="page">
      <section className="hero">
        <h1>Identrail</h1>
        <p>Machine identity risk intelligence for cloud workloads.</p>
      </section>

      <section className="panel">
        <label htmlFor="api-key">API Key</label>
        <input
          id="api-key"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="Optional for local dev"
        />
      </section>

      <section className="panel">
        <h2>Findings Summary</h2>
        {loading && <p>Loading...</p>}
        {error && <p className="error">{error}</p>}
        {!loading && !error && summary && (
          <>
            <p className="total">Total Findings: {summary.total}</p>
            <ul>
              {topSeverities.map(([severity, count]) => (
                <li key={severity}>
                  <strong>{severity}</strong>: {count}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </main>
  );
}
