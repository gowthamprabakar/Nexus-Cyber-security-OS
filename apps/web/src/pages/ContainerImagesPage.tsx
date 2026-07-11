import { useCallback, useEffect, useState } from 'react';
import { getContainerImages } from '../api/client';
import type { ContainerImage } from '../api/types';
import { useTenant } from '../auth/TenantProvider';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; rows: ContainerImage[] };

export function ContainerImagesPage() {
  const tenant = useTenant();
  const [state, setState] = useState<State>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const env = await getContainerImages(tenant);
      setState({ status: 'ready', rows: env.data });
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
        <h1>Container Images</h1>
        {state.status === 'ready' && (
          <span className="page__count">{state.rows.length} images</span>
        )}
      </header>

      {state.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading images…
        </div>
      )}
      {state.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load container images — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && state.rows.length === 0 && (
        <div className="state state--empty">
          No container images yet. Run an image scan to populate the registry inventory.
        </div>
      )}
      {state.status === 'ready' && state.rows.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Image</th>
              <th>Packages</th>
              <th>Vulnerabilities</th>
            </tr>
          </thead>
          <tbody>
            {state.rows.map((r) => (
              <tr key={r.id}>
                <td className="grid__id">{r.id}</td>
                <td>{r.packages}</td>
                <td>{r.vulnerabilities}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
