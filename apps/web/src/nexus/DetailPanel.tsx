// apps/web/src/nexus/DetailPanel.tsx
// Task 5: Real per-CVE detail drawer.
// Owns the full backdrop + panel (role="dialog"), replacing the placeholder.
import { useCallback, useEffect, useState } from 'react';
import { useTenant } from '../auth/TenantProvider';
import { getVulnerability } from '../api/client';
import { useFetch } from './useFetch';
import type { VulnDetail } from '../api/types';

// Severity palette — INLINED per task constraint (do NOT import from ListPage).
const SEV_HEX: Record<string, { fg: string; bg: string; l: string }> = {
  CRITICAL: { fg: '#E5484D', bg: 'var(--crit-bg,rgba(229,72,77,0.14))', l: 'C' },
  HIGH: { fg: '#F2820D', bg: 'var(--high-bg,rgba(242,130,13,0.14))', l: 'H' },
  MEDIUM: { fg: '#D9A40B', bg: 'var(--med-bg,rgba(217,164,11,0.14))', l: 'M' },
  LOW: { fg: '#4C8DFF', bg: 'var(--low-bg,rgba(76,141,255,0.14))', l: 'L' },
};
function sevStyle(severity: string | undefined | null) {
  if (!severity) return { fg: 'var(--text2)', bg: 'var(--surface)', l: '?' };
  return SEV_HEX[severity.toUpperCase()] ?? { fg: 'var(--text2)', bg: 'var(--surface)', l: '?' };
}

// Capitalise first letter, lower-case rest (e.g. "CRITICAL" → "Critical").
// Null-safe: returns '—' for undefined/null/empty input.
function capFirst(s: string | undefined | null) {
  if (!s) return '—';
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

// Inline gap note — plain, muted, no external import.
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
        marginBottom: 6,
      }}
    >
      {children}
    </div>
  );
}

type Tab = 'overview' | 'code' | 'investigation' | 'history' | 'comments';
const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'code', label: 'Code to Cloud' },
  { id: 'investigation', label: 'Investigation' },
  { id: 'history', label: 'History' },
  { id: 'comments', label: 'Comments' },
];

// ── Overview body ──────────────────────────────────────────────────────────────
function OverviewBody({ detail }: { detail: VulnDetail }) {
  const sev = sevStyle(detail.severity);
  return (
    <>
      {/* Description */}
      <div style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text2)', marginBottom: 18 }}>
        {detail.description}
      </div>

      {/* Detail grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr 1fr',
          gap: '14px 18px',
          marginBottom: 16,
        }}
      >
        {/* Severity */}
        <div>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Severity</div>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              height: 22,
              padding: '0 9px 0 7px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 500,
              background: sev.bg,
              color: sev.fg,
            }}
          >
            <span
              style={{
                fontFamily: "'IBM Plex Mono',monospace",
                fontWeight: 700,
              }}
            >
              {sev.l}
            </span>
            {capFirst(detail.severity)}
          </span>
        </div>
        {/* Fixed Version — primary remediation at-a-glance fact (per port guide) */}
        <div>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Fixed Version</div>
          <div
            style={{
              fontFamily: "'IBM Plex Mono',monospace",
              fontSize: 12,
              color: 'var(--accent,#4C8DFF)',
            }}
          >
            {detail.fix_version || '—'}
          </div>
        </div>
        {/* NVD Severity — mock's honest "Awaiting analysis" */}
        <div>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>NVD Severity</div>
          <div style={{ fontSize: 12, color: 'var(--text2)' }}>Awaiting analysis</div>
        </div>
        {/* Component */}
        <div>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Component</div>
          <div
            style={{ fontFamily: "'IBM Plex Mono',monospace", fontSize: 12, color: 'var(--text)' }}
          >
            {detail.component || '—'}
          </div>
        </div>
        {/* CVSS v3 — real */}
        <div>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>CVSS v3</div>
          <div style={{ fontFamily: "'IBM Plex Mono',monospace", fontSize: 12, color: sev.fg }}>
            {detail.cvss_v3_score != null ? String(detail.cvss_v3_score) : '—'}
          </div>
        </div>
        {/* CWE — real, optional-chained defensively */}
        <div>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>CWE</div>
          <div
            style={{ fontFamily: "'IBM Plex Mono',monospace", fontSize: 12, color: 'var(--text2)' }}
          >
            {detail.cwe?.length > 0 ? detail.cwe.join(', ') : '—'}
          </div>
        </div>
        {/* EPSS + KEV */}
        <div>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>EPSS / KEV</div>
          <div style={{ fontSize: 12, color: 'var(--text2)', display: 'flex', gap: 6 }}>
            <span>{detail.epss != null ? `${((detail.epss ?? 0) * 100).toFixed(1)}%` : '—'}</span>
            {detail.kev && (
              <span
                style={{
                  fontFamily: "'IBM Plex Mono',monospace",
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '1px 6px',
                  borderRadius: 5,
                  background: 'var(--crit-bg,rgba(229,72,77,0.14))',
                  color: '#E5484D',
                }}
              >
                KEV
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Affected Resources — optional-chained defensively */}
      {(detail.affected_resources?.length ?? 0) > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div
            style={{
              fontFamily: "'IBM Plex Mono',monospace",
              fontSize: 10.5,
              letterSpacing: '0.1em',
              color: 'var(--text3)',
              marginBottom: 8,
            }}
          >
            AFFECTED RESOURCES
          </div>
          <div
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 9,
              overflow: 'hidden',
            }}
          >
            {detail.affected_resources?.map((r) => (
              <div
                key={r}
                style={{
                  padding: '8px 14px',
                  fontFamily: "'IBM Plex Mono',monospace",
                  fontSize: 12,
                  color: 'var(--text2)',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                {r}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Remediation — real advice */}
      <div style={{ marginBottom: 16 }}>
        <div
          style={{
            fontFamily: "'IBM Plex Mono',monospace",
            fontSize: 10.5,
            letterSpacing: '0.1em',
            color: 'var(--text3)',
            marginBottom: 8,
          }}
        >
          TIER {detail.remediation?.tier?.toUpperCase() ?? '?'} · RECOMMENDED STEPS
        </div>
        <div
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 9,
            padding: '12px 14px',
            fontSize: 12.5,
            color: 'var(--text2)',
            lineHeight: 1.5,
          }}
        >
          <span
            style={{
              fontFamily: "'IBM Plex Mono',monospace",
              fontSize: 10,
              color: 'var(--text3)',
              marginRight: 6,
            }}
          >
            ▸
          </span>
          <span>{detail.remediation?.advice}</span>
        </div>
      </div>

      {/* Cure / Remediate gap note */}
      <div
        style={{
          background: 'var(--surface)',
          border: '1.5px solid var(--border)',
          borderRadius: 11,
          padding: 14,
          marginBottom: 14,
        }}
      >
        <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text2)', marginBottom: 6 }}>
          Let Cure remediate this
        </div>
        <GapNote>
          — needs the cloud remediation engine (safety-critical); Cure is not built yet
        </GapNote>
        <button
          disabled
          title="Not available yet"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            height: 32,
            padding: '0 14px',
            borderRadius: 8,
            border: 'none',
            background: 'var(--surface2)',
            color: 'var(--text3)',
            fontFamily: 'inherit',
            fontSize: 13,
            fontWeight: 600,
            cursor: 'not-allowed',
            opacity: 0.5,
          }}
        >
          Launch Custom Remediation →
        </button>
      </div>
    </>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────
export function DetailPanel({
  row,
  onClose,
}: {
  row: Record<string, unknown>;
  onClose: () => void;
}) {
  const tenant = useTenant();
  const cveId = String(row.cve ?? '');
  const rowStatus = String(row.status ?? 'Unresolved');

  // useFetch requires a stable callback — useCallback avoids spurious re-fetches.
  const fetchFn = useCallback((t: string) => getVulnerability(t, cveId), [cveId]);
  const state = useFetch(fetchFn, tenant);

  const [activeTab, setActiveTab] = useState<Tab>('overview');

  // Fix 3: Escape key closes the drawer (ARIA keyboard pattern).
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  // Severity for header icon — defensive: fall back to row.severity when detail not loaded.
  const detailSev = state.status === 'ready' ? (state.data.data?.severity ?? null) : null;
  const headerSev = sevStyle(detailSev ?? String(row.severity ?? ''));
  const headerTitle = cveId || '—';
  const headerKind = 'Vulnerability Finding';

  return (
    /* Full-screen backdrop — click closes */
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.4)',
        display: 'flex',
        justifyContent: 'flex-end',
        zIndex: 50,
      }}
    >
      {/* Panel — click does NOT propagate to backdrop */}
      <div
        role="dialog"
        aria-label="Finding detail"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '62%',
          maxWidth: 860,
          height: '100%',
          background: 'var(--bg)',
          borderLeft: '1px solid var(--border2)',
          overflowY: 'auto',
          boxShadow: '-20px 0 50px rgba(0,0,0,0.35)',
        }}
      >
        {/* ── Header ── */}
        <div style={{ padding: '18px 22px 0' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            {/* Severity icon */}
            <div
              style={{
                width: 30,
                height: 30,
                borderRadius: 7,
                background: headerSev.bg,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flex: 'none',
                marginTop: 2,
              }}
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke={headerSev.fg}
                strokeWidth={1.8}
              >
                <path d="M12 7a5 5 0 0 1 5 5v3a5 5 0 0 1-10 0v-3a5 5 0 0 1 5-5z" />
              </svg>
            </div>
            {/* Title + kind */}
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{
                  fontFamily: "'IBM Plex Mono',monospace",
                  fontSize: 17,
                  fontWeight: 600,
                  letterSpacing: '-0.01em',
                }}
              >
                {headerTitle}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>{headerKind}</div>
            </div>
            {/* Close button (prev/next omitted — deferred) */}
            <div style={{ display: 'flex', gap: 6, flex: 'none' }}>
              <button
                onClick={onClose}
                aria-label="Close"
                style={{
                  width: 30,
                  height: 30,
                  borderRadius: 7,
                  border: '1px solid var(--border2)',
                  background: 'transparent',
                  color: 'var(--text2)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <svg
                  width="15"
                  height="15"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path d="M18 6 6 18M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>

          {/* Action row */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              margin: '16px 0 4px',
            }}
          >
            {/* Remediate — gap (Cure not built) */}
            <button
              disabled
              title="Not available yet"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 7,
                height: 32,
                padding: '0 14px',
                borderRadius: 8,
                border: 'none',
                background: 'var(--surface2)',
                color: 'var(--text3)',
                fontFamily: 'inherit',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'not-allowed',
                opacity: 0.5,
              }}
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path d="M14.7 6.3a4 4 0 0 1 0 5.6l-1 1L8 7.3l1-1a4 4 0 0 1 5.6 0zM6 9l-3.5 9L11 14.5" />
              </svg>
              Remediate
            </button>
            {/* Ignore — honest no-op */}
            <button
              title="Not available yet"
              onClick={(e) => e.preventDefault()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 7,
                height: 32,
                padding: '0 12px',
                borderRadius: 8,
                border: '1px solid var(--border2)',
                background: 'transparent',
                color: 'var(--text2)',
                fontFamily: 'inherit',
                fontSize: 13,
                cursor: 'not-allowed',
                opacity: 0.6,
              }}
            >
              Ignore
            </button>
            {/* Support — honest no-op */}
            <button
              title="Not available yet"
              onClick={(e) => e.preventDefault()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 7,
                height: 32,
                padding: '0 12px',
                borderRadius: 8,
                border: '1px solid var(--border2)',
                background: 'transparent',
                color: 'var(--text2)',
                fontFamily: 'inherit',
                fontSize: 13,
                cursor: 'not-allowed',
                opacity: 0.6,
              }}
            >
              Support
            </button>
          </div>
        </div>

        {/* ── Body grid: left (tabs) + right (sidebar) ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 220px', gap: 0 }}>
          {/* Left column */}
          <div style={{ padding: '18px 22px', minWidth: 0 }}>
            {/* Tab bar */}
            <div
              role="tablist"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 16,
                borderBottom: '1px solid var(--border)',
                marginBottom: 16,
                flexWrap: 'wrap',
                rowGap: 2,
              }}
            >
              {TABS.map((t) => (
                <div
                  key={t.id}
                  role="tab"
                  aria-selected={activeTab === t.id}
                  onClick={() => setActiveTab(t.id)}
                  style={{
                    fontSize: 13,
                    fontWeight: activeTab === t.id ? 600 : 400,
                    color: activeTab === t.id ? 'var(--text)' : 'var(--text3)',
                    paddingBottom: 9,
                    borderBottom:
                      activeTab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
                    marginBottom: -1,
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {t.label}
                </div>
              ))}
            </div>

            {/* Tab content */}
            {activeTab === 'overview' && (
              <>
                {state.status === 'loading' && (
                  <div style={{ fontSize: 13, color: 'var(--text3)', padding: '20px 0' }}>
                    Loading…
                  </div>
                )}
                {state.status === 'error' && (
                  <div style={{ fontSize: 13, color: 'var(--text3)', padding: '20px 0' }}>
                    <span>{state.message}</span>{' '}
                    <button
                      onClick={state.retry}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--accent)',
                        cursor: 'pointer',
                        fontSize: 13,
                        padding: 0,
                      }}
                    >
                      Retry
                    </button>
                  </div>
                )}
                {state.status === 'ready' && state.data.data && (
                  <OverviewBody detail={state.data.data as VulnDetail} />
                )}
              </>
            )}
            {activeTab === 'code' && (
              <GapNote>— Code to Cloud tab needs the attack-path producer (not built yet)</GapNote>
            )}
            {activeTab === 'investigation' && (
              <GapNote>
                — Investigation tab needs the attack-path / CDR producer (not built yet)
              </GapNote>
            )}
            {activeTab === 'history' && (
              <GapNote>— History tab needs an event-history producer (not built yet)</GapNote>
            )}
            {activeTab === 'comments' && (
              <GapNote>— Comments tab needs a comments store (not built yet)</GapNote>
            )}
          </div>

          {/* Right sidebar */}
          <div
            style={{
              padding: '18px 20px',
              borderLeft: '1px solid var(--border)',
              background: 'var(--surface)',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 15 }}>
              {/* Status — real from row */}
              <div>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Status</div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    fontSize: 12.5,
                    color: '#E5484D',
                  }}
                >
                  <span
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      background: '#E5484D',
                      display: 'inline-block',
                    }}
                  />
                  {rowStatus}
                </div>
              </div>
              {/* First seen — real from VulnDetail */}
              <div>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>
                  First seen
                </div>
                <div
                  style={{
                    fontFamily: "'IBM Plex Mono',monospace",
                    fontSize: 11.5,
                    color: 'var(--text2)',
                  }}
                >
                  {state.status === 'ready' &&
                  state.data.data &&
                  'first_seen' in (state.data.data as object)
                    ? ((state.data.data as VulnDetail).first_seen ?? '—')
                    : '—'}
                </div>
              </div>
              {/* Gap sidebar fields */}
              <div style={{ height: 1, background: 'var(--border)' }} />
              <div>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>
                  Last seen
                </div>
                <GapNote>— needs a last-seen producer</GapNote>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Due At</div>
                <GapNote>— needs an SLA/due-date producer</GapNote>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>
                  Related Tickets
                </div>
                <button
                  disabled
                  title="Not available yet"
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--text3)',
                    fontSize: 12.5,
                    cursor: 'not-allowed',
                    padding: 0,
                    opacity: 0.5,
                  }}
                >
                  + Create ticket
                </button>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Assignee</div>
                <GapNote>— needs an assignee store</GapNote>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
