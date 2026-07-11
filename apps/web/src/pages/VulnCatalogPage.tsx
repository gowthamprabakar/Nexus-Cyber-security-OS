import { useCallback, useEffect, useState } from 'react';
import { getCatalog } from '../api/client';
import type { CatalogEntry } from '../api/types';
import { useTenant } from '../auth/TenantProvider';
import { RowCount } from '../components/RowCount';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; rows: CatalogEntry[]; total: number | null };

export function VulnCatalogPage() {
  const tenant = useTenant();
  const [state, setState] = useState<State>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const env = await getCatalog(tenant, { limit: 500 });
      setState({ status: 'ready', rows: env.data, total: env.meta.total });
    } catch (err) {
      setState({ status: 'error', message: err instanceof Error ? err.message : 'Unknown error' });
    }
  }, [tenant]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="page">
      <header className="page__head">
        <h1>Vulnerability Catalog</h1>
        {state.status === 'ready' && (
          <RowCount shown={state.rows.length} total={state.total} noun="unique CVEs" />
        )}
      </header>

      {state.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading catalog…
        </div>
      )}
      {state.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load the catalog — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && state.rows.length === 0 && (
        <div className="state state--empty">
          No CVEs catalogued yet. Run a scan to populate the catalog.
        </div>
      )}
      {state.status === 'ready' && state.rows.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>CVE</th>
              <th>Severity</th>
              <th>KEV</th>
              <th>EPSS</th>
              <th>Affected resources</th>
            </tr>
          </thead>
          <tbody>
            {state.rows.map((r) => (
              <tr key={r.cve_id}>
                <td className="grid__id">{r.cve_id}</td>
                <td>
                  <span className={`sev sev--${r.severity.toLowerCase()}`}>{r.severity}</span>
                </td>
                <td>{r.kev ? 'KEV' : '—'}</td>
                <td>{r.epss != null ? r.epss.toFixed(2) : '—'}</td>
                <td>{r.affected_resources}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
