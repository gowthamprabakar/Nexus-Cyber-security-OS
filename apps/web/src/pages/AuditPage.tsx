import { useCallback, useEffect, useState } from 'react';
import { getAuditEvents } from '../api/client';
import type { AuditEvent } from '../api/types';
import { useTenant } from '../auth/TenantProvider';
import { RowCount } from '../components/RowCount';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; rows: AuditEvent[]; total: number | null };

export function AuditPage() {
  const tenant = useTenant();
  const [state, setState] = useState<State>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const env = await getAuditEvents(tenant);
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
        <h1>Audit Log</h1>
        {state.status === 'ready' && (
          <RowCount shown={state.rows.length} total={state.total} noun="events" />
        )}
      </header>
      <p className="page__note">
        Tamper-evident record of every action taken on the platform (hash-chained, tenant-scoped),
        oldest first.
      </p>

      {state.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading audit log…
        </div>
      )}
      {state.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load the audit log — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && state.rows.length === 0 && (
        <div className="state state--empty">
          No audit events yet. Actions are recorded here as agents run.
        </div>
      )}
      {state.status === 'ready' && state.rows.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>Time</th>
              <th>Agent</th>
              <th>Action</th>
              <th>Correlation</th>
            </tr>
          </thead>
          <tbody>
            {state.rows.map((e, i) => (
              <tr key={`${e.correlation_id}:${e.action}:${i}`}>
                <td className="grid__id">{e.emitted_at}</td>
                <td>{e.agent_id}</td>
                <td>{e.action}</td>
                <td className="grid__id">{e.correlation_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
