import { useCallback, useEffect, useState } from 'react';
import { getAuditEvents, getAuditVerify } from '../api/client';
import type { AuditEvent, ChainStatus } from '../api/types';
import { useTenant } from '../auth/TenantProvider';

type State =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; events: AuditEvent[]; chain: ChainStatus };

function verdictText(chain: ChainStatus): string {
  if (chain.valid) return 'hash-chained · integrity verified';
  return (
    'TAMPER DETECTED at ' + (chain.broken_at_action ?? chain.broken_at_correlation_id ?? 'unknown')
  );
}

function exportJson(events: AuditEvent[]): void {
  const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'chain-export.json';
  a.click();
  URL.revokeObjectURL(url);
}

export function AuditChain() {
  const tenant = useTenant();
  const [state, setState] = useState<State>({ status: 'loading' });

  const load = useCallback(async () => {
    setState({ status: 'loading' });
    try {
      const [eventsEnv, verifyEnv] = await Promise.all([
        getAuditEvents(tenant),
        getAuditVerify(tenant),
      ]);
      setState({ status: 'ready', events: eventsEnv.data, chain: verifyEnv.data });
    } catch (err) {
      setState({ status: 'error', message: err instanceof Error ? err.message : 'Unknown error' });
    }
  }, [tenant]);

  const reVerify = useCallback(async () => {
    if (state.status !== 'ready') return;
    try {
      const verifyEnv = await getAuditVerify(tenant);
      setState((prev) => (prev.status === 'ready' ? { ...prev, chain: verifyEnv.data } : prev));
    } catch {
      // non-fatal: badge stays with last known result
    }
  }, [tenant, state.status]);

  useEffect(() => {
    void load();
  }, [load]);

  const isValid = state.status === 'ready' && state.chain.valid;
  const verifiedColor = 'rgb(139,147,255)';
  const verifiedBg = 'rgba(139,147,255,0.12)';
  const textMuted = 'rgba(255,255,255,0.45)';
  const textSub = 'rgba(255,255,255,0.65)';
  const surface = 'rgba(255,255,255,0.04)';
  const border = 'rgba(255,255,255,0.1)';
  const border2 = 'rgba(255,255,255,0.18)';

  return (
    <div style={{ padding: '18px 22px 40px', maxWidth: '1080px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
        <svg
          width="17"
          height="17"
          viewBox="0 0 24 24"
          fill="none"
          stroke={verifiedColor}
          strokeWidth="1.8"
        >
          <path d="M10 13a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1" />
        </svg>
        <h1 style={{ fontSize: '21px', fontWeight: 600, letterSpacing: '-0.02em', margin: 0 }}>
          Audit Chain
        </h1>

        {/* Verdict badge — driven by real getAuditVerify result */}
        {state.status === 'ready' && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              height: '24px',
              padding: '0 10px',
              borderRadius: '999px',
              background: isValid ? verifiedBg : 'rgba(220,50,50,0.12)',
              color: isValid ? verifiedColor : '#e05',
              fontSize: '11.5px',
              fontWeight: 500,
            }}
          >
            <svg
              width="11"
              height="11"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
            >
              <path d="M20 6 9 17l-5-5" />
            </svg>
            {verdictText(state.chain)}
          </div>
        )}

        <div style={{ flex: 1 }} />

        {/* Export JSON button */}
        <button
          type="button"
          onClick={() => state.status === 'ready' && exportJson(state.events)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            height: '30px',
            padding: '0 12px',
            borderRadius: '7px',
            border: `1px solid ${border2}`,
            background: 'transparent',
            color: textSub,
            fontFamily: 'inherit',
            fontSize: '12.5px',
            cursor: 'pointer',
          }}
        >
          <svg
            width="13"
            height="13"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
          >
            <path d="M12 3v12M7 10l5 5 5-5M5 21h14" />
          </svg>
          Export JSON
        </button>

        {/* Verify integrity button */}
        <button
          type="button"
          onClick={() => void reVerify()}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            height: '30px',
            padding: '0 12px',
            borderRadius: '7px',
            border: `1px solid rgba(139,147,255,0.45)`,
            background: verifiedBg,
            color: verifiedColor,
            fontFamily: 'inherit',
            fontSize: '12.5px',
            cursor: 'pointer',
            fontWeight: 500,
          }}
        >
          <svg
            width="13"
            height="13"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
          </svg>
          Verify integrity
        </button>
      </div>

      {/* Description — hash-chained, no signing claim */}
      <p style={{ fontSize: '13px', color: textMuted, margin: '0 0 22px' }}>
        Every agent action is logged as a SHA-256 hash-chained entry linked to its parent.
      </p>

      {/* Loading state */}
      {state.status === 'loading' && (
        <div role="status" aria-live="polite" style={{ color: textMuted, fontSize: '13px' }}>
          Loading audit chain…
        </div>
      )}

      {/* Error state */}
      {state.status === 'error' && (
        <div role="alert" style={{ color: '#e05', fontSize: '13px' }}>
          <p>Could not load audit chain — {state.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      {/* Ready — vertical timeline */}
      {state.status === 'ready' && state.events.length === 0 && (
        <div style={{ color: textMuted, fontSize: '13px' }}>
          No audit events yet. Actions are recorded here as agents run.
        </div>
      )}

      {state.status === 'ready' && state.events.length > 0 && (
        <div style={{ position: 'relative', paddingLeft: '26px' }}>
          {/* Gradient spine */}
          <div
            style={{
              position: 'absolute',
              left: '9px',
              top: '6px',
              bottom: '6px',
              width: '2px',
              background: `linear-gradient(180deg,${verifiedColor},${border2})`,
            }}
          />

          {state.events.map((e, i) => (
            <div
              key={`${e.correlation_id}:${e.action}:${i}`}
              style={{ position: 'relative', marginBottom: '14px' }}
            >
              {/* Timeline dot */}
              <div
                style={{
                  position: 'absolute',
                  left: '-22px',
                  top: '18px',
                  width: '12px',
                  height: '12px',
                  borderRadius: '50%',
                  background: '#0f1117',
                  border: `2px solid ${verifiedColor}`,
                }}
              />

              {/* Entry card — real AuditEvent fields only */}
              <div
                style={{
                  background: surface,
                  border: `1px solid ${border}`,
                  borderRadius: '11px',
                  padding: '14px 16px',
                }}
              >
                {/* Action title + time */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    marginBottom: '11px',
                    flexWrap: 'wrap',
                  }}
                >
                  <span
                    style={{
                      fontSize: '12px',
                      color: 'rgba(255,255,255,0.9)',
                      fontWeight: 600,
                    }}
                  >
                    {e.action}
                  </span>
                  <div style={{ flex: 1 }} />
                  <span
                    style={{
                      fontFamily: "'IBM Plex Mono',monospace",
                      fontSize: '11px',
                      color: textMuted,
                    }}
                  >
                    {e.emitted_at}
                  </span>
                </div>

                {/* Real fields grid: agent_id, correlation_id, source */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '10px 24px',
                    fontFamily: "'IBM Plex Mono',monospace",
                    fontSize: '11.5px',
                    lineHeight: 1.6,
                  }}
                >
                  <div>
                    <span style={{ color: textMuted }}>agent </span>
                    <span style={{ color: textSub }}>{e.agent_id}</span>
                  </div>
                  <div>
                    <span style={{ color: textMuted }}>correlation </span>
                    <span style={{ color: textSub }}>{e.correlation_id}</span>
                  </div>
                  <div style={{ gridColumn: '1 / -1' }}>
                    <span style={{ color: textMuted }}>source </span>
                    <span style={{ color: textSub }}>{e.source}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
