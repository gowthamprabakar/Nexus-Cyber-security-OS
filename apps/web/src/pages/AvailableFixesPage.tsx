import { useCallback, useEffect, useState } from 'react';
import { getAvailableFixes } from '../api/client';
import type { AvailableFix } from '../api/types';
import { useTenant } from '../auth/TenantProvider';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; rows: AvailableFix[] };

export function AvailableFixesPage() {
  const tenant = useTenant();
  const [state, setState] = useState<State>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const env = await getAvailableFixes(tenant);
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
        <h1>Available Fixes</h1>
        {state.status === 'ready' && (
          <span className="page__count">{state.rows.length} patch actions</span>
        )}
      </header>
      <p className="page__note">
        Upgrades already published for your findings, ranked by how many CVEs each clears.
        Deployment tracking and one-click apply depend on the Remediation chapter.
      </p>

      {state.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading fixes…
        </div>
      )}
      {state.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load available fixes — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && state.rows.length === 0 && (
        <div className="state state--empty">
          No published fixes for current findings. Vulnerabilities without a fix version appear
          under Vulnerabilities.
        </div>
      )}
      {state.status === 'ready' && state.rows.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Package</th>
              <th>Upgrade to</th>
              <th>CVEs fixed</th>
              <th>Resources</th>
              <th>Worst severity</th>
            </tr>
          </thead>
          <tbody>
            {state.rows.map((r) => (
              <tr key={`${r.component}@${r.fix_version}`}>
                <td>{r.component || '—'}</td>
                <td className="grid__id">{r.fix_version}</td>
                <td>{r.cve_count}</td>
                <td>{r.resource_count}</td>
                <td>
                  <span className={`sev sev--${r.max_severity.toLowerCase()}`}>
                    {r.max_severity || '—'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
