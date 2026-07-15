// apps/web/src/nexus/Overview.tsx
// §9 #5: the Vulnerability Overview board, wired to the real /v1/posture aggregate.
// Everything shown here is computed by the posture engine — severity distribution,
// coverage, and the exposure funnel. Widgets the mock shows that posture does NOT
// produce (security score, avg issue age, opened-vs-resolved trend, Cure queue) are
// honest gap notes, not fabricated numbers, until their producers land.
import { useCallback } from 'react';
import { useTenant } from '../auth/TenantProvider';
import { getPosture } from '../api/client';
import { useFetch } from './useFetch';
import type { PostureSummary } from '../api/types';

const SEV = [
  { key: 'critical', label: 'Critical', fg: '#E5484D', bg: 'var(--crit-bg)', l: 'C' },
  { key: 'high', label: 'High', fg: '#F2820D', bg: 'var(--high-bg)', l: 'H' },
  { key: 'medium', label: 'Medium', fg: '#D9A40B', bg: 'var(--med-bg)', l: 'M' },
  { key: 'low', label: 'Low', fg: '#4C8DFF', bg: 'var(--low-bg)', l: 'L' },
] as const;

const card: React.CSSProperties = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 11,
  padding: '15px 16px',
};
const cardTitle: React.CSSProperties = {
  fontSize: 12,
  color: 'var(--text2)',
  marginBottom: 13,
  fontWeight: 500,
};

function GapNote({ children }: { children: string }) {
  return (
    <div
      style={{
        fontSize: 11.5,
        color: 'var(--text3)',
        fontStyle: 'italic',
        padding: '10px 12px',
        border: '1px solid var(--border)',
        borderRadius: 8,
      }}
    >
      {children}
    </div>
  );
}

function Board({ posture }: { posture: PostureSummary }) {
  const sd = posture.severity_distribution;
  const f = posture.exposure_funnel;
  const cov = posture.coverage;
  const funnel: { label: string; value: number; fg: string }[] = [
    { label: 'Exposed', value: f.exposed, fg: 'var(--text)' },
    { label: 'Vulnerable', value: f.vulnerable, fg: '#F2820D' },
    { label: 'KEV', value: f.kev, fg: '#E5484D' },
    { label: 'Exploitable', value: f.exploitable, fg: '#E5484D' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Top row: severity distribution + coverage */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr 1fr', gap: 12 }}>
        {/* Open Issues by Severity — real */}
        <div style={card}>
          <div style={cardTitle}>Open Issues by Severity</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
            {SEV.map((s) => (
              <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                <span
                  style={{
                    width: 18,
                    height: 18,
                    borderRadius: 5,
                    background: s.bg,
                    color: s.fg,
                    fontSize: 11,
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontFamily: "'IBM Plex Mono',monospace",
                  }}
                >
                  {s.l}
                </span>
                <span
                  style={{
                    fontFamily: "'IBM Plex Mono',monospace",
                    fontSize: 17,
                    fontWeight: 600,
                  }}
                >
                  {sd[s.key]}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text3)' }}>{s.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Coverage — real */}
        <div style={card}>
          <div style={cardTitle}>Coverage</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <CoverageRow label="Findings surfaced" pct={cov.surfaced_pct} />
            <CoverageRow label="Domains covered" pct={cov.domain_pct} />
            {cov.collector_pct != null && (
              <CoverageRow label="Collectors healthy" pct={cov.collector_pct} />
            )}
          </div>
        </div>

        {/* Exposure funnel — real (exposed → vulnerable → KEV → exploitable) */}
        <div style={card}>
          <div style={cardTitle}>Exposure Funnel</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {funnel.map((row) => (
              <div
                key={row.label}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
              >
                <span style={{ fontSize: 12, color: 'var(--text3)' }}>{row.label}</span>
                <span
                  style={{
                    fontFamily: "'IBM Plex Mono',monospace",
                    fontSize: 14,
                    fontWeight: 600,
                    color: row.fg,
                  }}
                >
                  {row.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* By domain — real */}
      {posture.by_domain.length > 0 && (
        <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
          <div style={{ ...cardTitle, padding: '14px 16px 0', marginBottom: 10 }}>
            Findings by Domain
          </div>
          <div
            style={{
              display: 'flex',
              padding: '0 16px',
              height: 32,
              alignItems: 'center',
              borderBottom: '1px solid var(--border)',
              fontFamily: "'IBM Plex Mono',monospace",
              fontSize: 10.5,
              letterSpacing: '0.04em',
              color: 'var(--text3)',
              textTransform: 'uppercase',
              gap: 14,
            }}
          >
            <span style={{ flex: 2 }}>Domain</span>
            <span style={{ flex: 1, textAlign: 'right' }}>Critical</span>
            <span style={{ flex: 1, textAlign: 'right' }}>High</span>
            <span style={{ flex: 1, textAlign: 'right' }}>Total</span>
          </div>
          {posture.by_domain.map((d) => (
            <div
              key={d.domain}
              style={{
                display: 'flex',
                padding: '0 16px',
                minHeight: 40,
                alignItems: 'center',
                borderBottom: '1px solid var(--border)',
                fontSize: 12.5,
                gap: 14,
              }}
            >
              <span style={{ flex: 2, color: 'var(--text)' }}>{d.domain}</span>
              <span
                style={{
                  flex: 1,
                  textAlign: 'right',
                  fontFamily: "'IBM Plex Mono',monospace",
                  color: '#E5484D',
                }}
              >
                {d.critical}
              </span>
              <span
                style={{
                  flex: 1,
                  textAlign: 'right',
                  fontFamily: "'IBM Plex Mono',monospace",
                  color: '#F2820D',
                }}
              >
                {d.high}
              </span>
              <span
                style={{
                  flex: 1,
                  textAlign: 'right',
                  fontFamily: "'IBM Plex Mono',monospace",
                  color: 'var(--text2)',
                }}
              >
                {d.total}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Honest gaps — widgets the mock shows but posture does not produce yet */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div style={card}>
          <div style={cardTitle}>Vulnerability Trend</div>
          <GapNote>— needs a time-series / trend producer (not built yet)</GapNote>
        </div>
        <div style={card}>
          <div style={cardTitle}>Time to Patch by Severity</div>
          <GapNote>— needs a remediation-timing producer (not built yet)</GapNote>
        </div>
      </div>
    </div>
  );
}

function CoverageRow({ label, pct }: { label: string; pct: number }) {
  const clamped = Math.max(0, Math.min(100, pct));
  const bar = clamped >= 90 ? '#3FB07F' : clamped >= 60 ? '#D9A40B' : '#E5484D';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12 }}>
      <span style={{ flex: 'none', width: 116, color: 'var(--text3)' }}>{label}</span>
      <div
        style={{
          flex: 1,
          height: 6,
          borderRadius: 4,
          background: 'var(--surface2)',
          overflow: 'hidden',
        }}
      >
        <div style={{ width: `${clamped}%`, height: '100%', background: bar }} />
      </div>
      <span
        style={{
          fontFamily: "'IBM Plex Mono',monospace",
          color: 'var(--text2)',
          width: 40,
          textAlign: 'right',
        }}
      >
        {Math.round(clamped)}%
      </span>
    </div>
  );
}

export function Overview() {
  const tenant = useTenant();
  const fetchFn = useCallback((t: string) => getPosture(t), []);
  const state = useFetch(fetchFn, tenant);

  return (
    <div style={{ padding: '18px 22px 40px', maxWidth: 1320 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
        <h1 style={{ fontSize: 21, fontWeight: 600, letterSpacing: '-0.02em', margin: 0 }}>
          Vulnerability Overview
        </h1>
      </div>
      <p style={{ fontSize: 13, color: 'var(--text3)', margin: '0 0 18px' }}>
        Posture aggregated by the scan engine — severity, coverage, and exposure narrowing.
      </p>

      {state.status === 'loading' && (
        <div style={{ padding: '40px 0', color: 'var(--text3)', fontSize: 12.5 }}>Loading…</div>
      )}
      {state.status === 'error' && (
        <div role="alert" style={{ padding: '32px 0', color: 'var(--text2)', fontSize: 12.5 }}>
          <div style={{ marginBottom: 12, color: '#E5484D' }}>Failed to load: {state.message}</div>
          <button
            onClick={state.retry}
            style={{
              height: 30,
              padding: '0 14px',
              borderRadius: 7,
              border: '1px solid var(--border2)',
              background: 'var(--surface2)',
              color: 'var(--text)',
              fontFamily: 'inherit',
              fontSize: 12.5,
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      )}
      {state.status === 'ready' && state.data.data && <Board posture={state.data.data} />}
    </div>
  );
}
