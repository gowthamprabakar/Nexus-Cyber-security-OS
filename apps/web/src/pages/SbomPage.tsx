import { useCallback, useEffect, useState } from 'react';
import { getSbom } from '../api/client';
import type { SbomPackage } from '../api/types';
import { useTenant } from '../auth/TenantProvider';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; rows: SbomPackage[] };

export function SbomPage() {
  const tenant = useTenant();
  const [state, setState] = useState<State>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const env = await getSbom(tenant);
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
        <h1>SBOM</h1>
        {state.status === 'ready' && (
          <span className="page__count">{state.rows.length} packages</span>
        )}
      </header>

      {state.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading packages…
        </div>
      )}
      {state.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load the SBOM — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && state.rows.length === 0 && (
        <div className="state state--empty">
          No SBOM packages yet. Run an image scan to populate the software bill of materials.
        </div>
      )}
      {state.status === 'ready' && state.rows.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Package</th>
              <th>Image</th>
              <th>Vulnerabilities</th>
            </tr>
          </thead>
          <tbody>
            {state.rows.map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td className="grid__id">{r.image}</td>
                <td>{r.vulnerabilities}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
