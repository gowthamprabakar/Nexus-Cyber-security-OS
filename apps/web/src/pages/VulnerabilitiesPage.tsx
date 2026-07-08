import { useCallback, useEffect, useState } from 'react';
import { getVulnerabilities, getVulnerability } from '../api/client';
import type { VulnDetail, VulnFinding } from '../api/types';
import { useTenant } from '../auth/TenantProvider';

type ListState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; rows: VulnFinding[] };

type DetailState =
  | { status: 'idle' }
  | { status: 'loading'; cveId: string }
  | { status: 'error'; cveId: string; message: string }
  | { status: 'ready'; detail: VulnDetail };

function message(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

export function VulnerabilitiesPage() {
  const tenant = useTenant();
  const [list, setList] = useState<ListState>({ status: 'loading' });
  const [detail, setDetail] = useState<DetailState>({ status: 'idle' });

  const loadList = useCallback(async () => {
    setList({ status: 'loading' });
    try {
      const env = await getVulnerabilities(tenant, { limit: 100 });
      setList({ status: 'ready', rows: env.data });
    } catch (err) {
      setList({ status: 'error', message: message(err) });
    }
  }, [tenant]);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  const openDetail = useCallback(
    async (cveId: string) => {
      setDetail({ status: 'loading', cveId });
      try {
        const env = await getVulnerability(tenant, cveId);
        setDetail({ status: 'ready', detail: env.data });
      } catch (err) {
        setDetail({ status: 'error', cveId, message: message(err) });
      }
    },
    [tenant]
  );

  return (
    <section className="page">
      <header className="page__head">
        <h1>Vulnerabilities</h1>
        {list.status === 'ready' && (
          <span className="page__count">{list.rows.length} findings</span>
        )}
      </header>

      {list.status === 'loading' && (
        <div className="state state--loading" role="status" aria-live="polite">
          Loading vulnerabilities…
        </div>
      )}
      {list.status === 'error' && (
        <div className="state state--error" role="alert">
          <p>Couldn’t load vulnerabilities — {list.message}</p>
          <button type="button" onClick={() => void loadList()}>
            Retry
          </button>
        </div>
      )}
      {list.status === 'ready' && list.rows.length === 0 && (
        <div className="state state--empty">
          No vulnerabilities found. Run a scan to populate this view.
        </div>
      )}
      {list.status === 'ready' && list.rows.length > 0 && (
        <div className="split">
          <table className="grid">
            <thead>
              <tr>
                <th>CVE</th>
                <th>Severity</th>
                <th>KEV</th>
                <th>EPSS</th>
                <th>Resource</th>
                <th>Component</th>
                <th>Fix</th>
              </tr>
            </thead>
            <tbody>
              {list.rows.map((r, i) => (
                <tr
                  key={`${r.cve_id}:${r.resource}:${i}`}
                  className="grid__row"
                  onClick={() => void openDetail(r.cve_id)}
                >
                  <td className="grid__id">{r.cve_id}</td>
                  <td>
                    <span className={`sev sev--${r.severity.toLowerCase()}`}>{r.severity}</span>
                  </td>
                  <td>{r.kev ? 'KEV' : '—'}</td>
                  <td>{r.epss != null ? r.epss.toFixed(2) : '—'}</td>
                  <td className="grid__id">{r.resource}</td>
                  <td>{r.component || '—'}</td>
                  <td>{r.fix_version || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {detail.status !== 'idle' && (
            <aside className="detail">
              {detail.status === 'loading' && (
                <div className="state state--loading" role="status">
                  Loading {detail.cveId}…
                </div>
              )}
              {detail.status === 'error' && (
                <div className="state state--error" role="alert">
                  <p>
                    Couldn’t load {detail.cveId} — {detail.message}
                  </p>
                  <button type="button" onClick={() => void openDetail(detail.cveId)}>
                    Retry
                  </button>
                </div>
              )}
              {detail.status === 'ready' && <VulnDetailView detail={detail.detail} />}
            </aside>
          )}
        </div>
      )}
    </section>
  );
}

function VulnDetailView({ detail }: { detail: VulnDetail }) {
  return (
    <div className="detail__body">
      <h2>{detail.cve_id}</h2>
      <dl className="kv">
        <dt>Severity</dt>
        <dd>{detail.severity}</dd>
        <dt>KEV</dt>
        <dd>{detail.kev ? 'Known-exploited' : 'No'}</dd>
        <dt>EPSS</dt>
        <dd>{detail.epss != null ? detail.epss.toFixed(2) : '—'}</dd>
        <dt>CVSS v3</dt>
        <dd>{detail.cvss_v3_score != null ? detail.cvss_v3_score.toFixed(1) : '—'}</dd>
        <dt>CWE</dt>
        <dd>{detail.cwe.length > 0 ? detail.cwe.join(', ') : '—'}</dd>
        <dt>Fix</dt>
        <dd>{detail.fix_version || 'None available'}</dd>
      </dl>
      {detail.description && <p className="detail__desc">{detail.description}</p>}
      <h3>Affected resources ({detail.affected_resources.length})</h3>
      <ul className="detail__resources">
        {detail.affected_resources.map((r) => (
          <li key={r} className="grid__id">
            {r}
          </li>
        ))}
      </ul>
      <h3>Remediation</h3>
      <p className="detail__advice">
        <span className="tier">{detail.remediation.tier}</span> {detail.remediation.advice}
      </p>
    </div>
  );
}
