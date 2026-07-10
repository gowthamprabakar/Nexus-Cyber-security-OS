import { useCallback, useEffect, useState } from 'react';
import { getPosture } from '../api/client';
import type { PostureSummary } from '../api/types';
import { useTenant } from '../auth/TenantProvider';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; posture: PostureSummary };

function isEmpty(p: PostureSummary): boolean {
  return (p.totals.attack_paths ?? 0) === 0 && (p.totals.findings ?? 0) === 0;
}

export function OverviewPage() {
  const tenant = useTenant();
  const [state, setState] = useState<State>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const env = await getPosture(tenant);
      setState({ status: 'ready', posture: env.data });
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
        <h1>Overview</h1>
      </header>
      {state.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading posture…
        </div>
      )}
      {state.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load posture — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && isEmpty(state.posture) && (
        <div className="state state--empty">
          No scan data yet. Connect a cloud account and run a scan to populate the board.
        </div>
      )}
      {state.status === 'ready' && !isEmpty(state.posture) && <Board posture={state.posture} />}
    </section>
  );
}

function Board({ posture }: { posture: PostureSummary }) {
  const c = posture.coverage;
  const s = posture.severity_distribution;
  const f = posture.exposure_funnel;
  const inventory = Object.entries(posture.inventory_counts);
  return (
    <div className="board">
      <div className="coverage">
        <span className="coverage__tag">Coverage</span>
        <span>
          <b>{c.domain_pct}%</b> of domains ({c.domains_covered}/{c.domains_total})
        </span>
        {c.collector_pct != null && (
          <span>
            <b>{c.collector_pct}%</b> of collectors ({c.collectors_ok}/{c.collectors_run})
          </span>
        )}
        <span>
          <b>{c.surfaced_pct}%</b> of findings surfaced ({c.surfaced_findings}/{c.total_findings})
        </span>
      </div>

      <div className="cards">
        <SevCard label="Critical" n={s.critical} kind="critical" />
        <SevCard label="High" n={s.high} kind="high" />
        <SevCard label="Medium" n={s.medium} kind="medium" />
        <SevCard label="Low" n={s.low} kind="low" />
      </div>

      <h3 className="board__h">Exposure funnel</h3>
      <div className="funnel">
        <FunnelStage label="Exposed" n={f.exposed} />
        <FunnelStage label="Vulnerable" n={f.vulnerable} />
        <FunnelStage label="KEV" n={f.kev} />
        <FunnelStage label="Exploitable" n={f.exploitable} />
      </div>

      {posture.by_domain.length > 0 && (
        <>
          <h3 className="board__h">By domain</h3>
          <table className="grid">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Total</th>
              </tr>
            </thead>
            <tbody>
              {posture.by_domain.map((d) => (
                <tr key={d.domain}>
                  <td>{d.domain}</td>
                  <td>{d.critical}</td>
                  <td>{d.high}</td>
                  <td>{d.medium}</td>
                  <td>{d.low}</td>
                  <td>{d.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {inventory.length > 0 && (
        <>
          <h3 className="board__h">Inventory</h3>
          <div className="inv">
            {inventory.map(([k, v]) => (
              <div className="inv__item" key={k}>
                <span className="inv__n">{v}</span>
                <span className="inv__k">{k}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function SevCard({ label, n, kind }: { label: string; n: number; kind: string }) {
  return (
    <div className={`card card--${kind}`}>
      <span className="card__n">{n}</span>
      <span className="card__l">{label}</span>
    </div>
  );
}

function FunnelStage({ label, n }: { label: string; n: number }) {
  return (
    <div className="funnel__stage">
      <span className="funnel__n">{n}</span>
      <span className="funnel__l">{label}</span>
    </div>
  );
}
