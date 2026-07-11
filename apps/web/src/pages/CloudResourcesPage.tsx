import { useCallback, useEffect, useState } from 'react';
import { getCloudResources } from '../api/client';
import type { CloudResource } from '../api/types';
import { useTenant } from '../auth/TenantProvider';
import { RowCount } from '../components/RowCount';

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; rows: CloudResource[]; total: number | null };

export function CloudResourcesPage() {
  const tenant = useTenant();
  const [state, setState] = useState<LoadState>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const env = await getCloudResources(tenant, { limit: 500 });
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
        <h1>Cloud Resources</h1>
        {state.status === 'ready' && (
          <RowCount shown={state.rows.length} total={state.total} noun="resources" />
        )}
      </header>

      {state.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading cloud resources…
        </div>
      )}

      {state.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load cloud resources — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      {state.status === 'ready' && state.rows.length === 0 && (
        <div className="state state--empty">
          No cloud resources yet. Connect a cloud account and run a scan to populate this view.
        </div>
      )}

      {state.status === 'ready' && state.rows.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Resource</th>
              <th>Kind</th>
              <th>Cloud</th>
              <th>Public</th>
              <th>Region</th>
            </tr>
          </thead>
          <tbody>
            {state.rows.map((r) => (
              <tr key={r.id}>
                <td className="grid__id">{r.id}</td>
                <td>{r.kind}</td>
                <td>{r.cloud}</td>
                <td>{r.is_public ? 'Yes' : 'No'}</td>
                <td>{r.region ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
