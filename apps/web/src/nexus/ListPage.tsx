import { useMemo, useState } from 'react';
import { useTenant } from '../auth/TenantProvider';
import { useFetch } from './useFetch';
import { LIST_CONFIG, type Column } from './listConfig';
import { DetailPanel } from './DetailPanel';
import type { View } from './nav';

// Severity palette — mirrors the mock's hardcoded chip colors + theme --*-bg vars.
const SEV: Record<string, { fg: string; bg: string; l: string; bar: string }> = {
  Critical: { fg: '#E5484D', bg: 'var(--crit-bg)', l: 'C', bar: '#E5484D' },
  High: { fg: '#F2820D', bg: 'var(--high-bg)', l: 'H', bar: '#F2820D' },
  Medium: { fg: '#D9A40B', bg: 'var(--med-bg)', l: 'M', bar: '#D9A40B' },
  Low: { fg: '#4C8DFF', bg: 'var(--low-bg)', l: 'L', bar: '#4C8DFF' },
};
const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low'] as const;

// Attribution "Discovered by X · extra" → split into the agent + optional extra.
function splitAttribution(a: string): { agent: string; extra: string | null } {
  const s = a.replace(/^Discovered by\s*/, '');
  const dot = s.indexOf(' · ');
  if (dot === -1) return { agent: s, extra: null };
  return { agent: s.slice(0, dot), extra: s.slice(dot + 3) };
}

const noop = () => {};

type Row = Record<string, unknown>;

const iconGraph = (
  <svg
    width="14"
    height="14"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={1.8}
  >
    <circle cx="6" cy="6" r="2"></circle>
    <circle cx="18" cy="9" r="2"></circle>
    <circle cx="9" cy="18" r="2"></circle>
    <path d="M8 7l8 1M8 16l3-6"></path>
  </svg>
);
const caretDown = (stroke: string) => (
  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={stroke} strokeWidth={2.4}>
    <path d="m6 9 6 6 6-6"></path>
  </svg>
);

// One table cell rendered per column.type (sev chip / status dot / two-line / mono / text).
function Cell({ column, row }: { column: Column; row: Row }) {
  const value = row[column.key];
  const text = value == null ? '' : String(value);
  const flex = column.fb ?? 1;
  const base: React.CSSProperties = { flex, minWidth: 0 };

  if (column.type === 'sev') {
    const s = SEV[text];
    if (!s) {
      return (
        <span style={base}>
          <span
            style={{
              color: 'var(--text)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              display: 'block',
            }}
          >
            {text}
          </span>
        </span>
      );
    }
    return (
      <span style={base}>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            height: 21,
            padding: '0 9px 0 7px',
            borderRadius: 6,
            fontSize: 11.5,
            fontWeight: 500,
            background: s.bg,
            color: s.fg,
          }}
        >
          <span style={{ fontFamily: "'IBM Plex Mono',monospace", fontWeight: 700 }}>{s.l}</span>
          {text}
        </span>
      </span>
    );
  }

  if (column.type === 'status') {
    return (
      <span style={base}>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 5,
            fontSize: 12,
            color: '#E5484D',
          }}
        >
          <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#E5484D' }}></span>
          {text}
        </span>
      </span>
    );
  }

  if (column.type === 'two') {
    const sub = row[`${column.key}_sub`];
    return (
      <span style={base}>
        <span
          style={{
            display: 'block',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            color: 'var(--text)',
          }}
        >
          {text}
        </span>
        {sub != null && (
          <span style={{ display: 'block', fontSize: 11, color: 'var(--text3)' }}>
            {String(sub)}
          </span>
        )}
      </span>
    );
  }

  if (column.type === 'mono') {
    return (
      <span style={base}>
        <span
          style={{
            fontFamily: "'IBM Plex Mono',monospace",
            fontSize: 11.5,
            color: 'var(--text2)',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            display: 'block',
          }}
        >
          {text}
        </span>
      </span>
    );
  }

  return (
    <span style={base}>
      <span
        style={{
          color: 'var(--text)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          display: 'block',
        }}
      >
        {text}
      </span>
    </span>
  );
}

function DataRow({
  columns,
  row,
  indent,
  onOpen,
}: {
  columns: Column[];
  row: Row;
  indent: boolean;
  onOpen: () => void;
}) {
  const [hover, setHover] = useState(false);
  return (
    <div
      onClick={onOpen}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex',
        padding: indent ? '0 16px 0 32px' : '0 16px',
        minHeight: 52,
        alignItems: 'center',
        borderBottom: '1px solid var(--border)',
        cursor: 'pointer',
        fontSize: 12.5,
        gap: 14,
        background: hover ? 'var(--hover)' : undefined,
      }}
    >
      {columns.map((c) => (
        <Cell key={c.key} column={c} row={row} />
      ))}
      <span
        onClick={(e) => {
          e.stopPropagation();
          noop();
        }}
        title="Not available yet"
        style={{
          flex: '0 0 26px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--text3)',
          opacity: 0.55,
        }}
      >
        {iconGraph}
      </span>
    </div>
  );
}

export function ListPage({ view }: { view: View }) {
  const tenant = useTenant();
  const config = LIST_CONFIG[view];
  if (!config) throw new Error(`No list config for view: ${view}`);
  const { title, attribution, columns } = config;
  const fetchFn = config.fetch;

  const state = useFetch<Row[]>(fetchFn, tenant);

  const [showLearn, setShowLearn] = useState(true);
  // Default is the flat/ungrouped view (mock's default state); tabs opt into grouping.
  const [group, setGroup] = useState<'rule' | 'resource' | 'subscription' | 'severity' | null>(
    null
  );
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set());
  const [sevMenuOpen, setSevMenuOpen] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);

  const allRows = state.status === 'ready' ? state.data : [];

  // REAL client-side severity filter on the loaded rows (empty = show all).
  const rows = useMemo(
    () =>
      sevFilter.size === 0 ? allRows : allRows.filter((r) => sevFilter.has(String(r.severity))),
    [allRows, sevFilter]
  );

  // DERIVED widgets — all computed from the (filtered) rows, never fabricated.
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const r of rows) {
      const s = String(r.severity);
      if (s in c) c[s] = (c[s] ?? 0) + 1;
    }
    return c;
  }, [rows]);

  // Top-N ranking of genuinely repeated values (count > 1); singletons aren't "top".
  const topN = (src: Row[], key: string) => {
    const m = new Map<string, number>();
    for (const r of src) {
      const k = String(r[key] ?? '');
      if (!k) continue;
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()]
      .filter(([, v]) => v > 1)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);
  };
  const widgetA = useMemo(() => topN(rows, 'cve'), [rows]); // Top by Rule
  const widgetB = useMemo(() => topN(rows, 'resource'), [rows]); // Top Resources

  // REAL group-by (null = flat/default; Subscription has no field → decorative, stays flat).
  const grouped = group === 'rule' || group === 'resource' || group === 'severity';
  const groups = useMemo(() => {
    if (!grouped) return [];
    const gk = group === 'rule' ? 'cve' : group === 'resource' ? 'resource' : 'severity';
    const m = new Map<string, Row[]>();
    for (const r of rows) {
      const k = String(r[gk] ?? '—');
      if (!m.has(k)) m.set(k, []);
      m.get(k)!.push(r);
    }
    return [...m.entries()].map(([key, gr]) => {
      const c = gr.filter((r) => r.severity === 'Critical').length;
      const h = gr.filter((r) => r.severity === 'High').length;
      const md = gr.filter((r) => r.severity === 'Medium').length;
      const l = gr.filter((r) => r.severity === 'Low').length;
      return { key, rows: gr, count: gr.length, c, h, m: md, l };
    });
  }, [rows, group, grouped]);

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const toggleGroup = (k: string) =>
    setCollapsed((prev) => {
      const n = new Set(prev);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });

  const { agent, extra } = splitAttribution(attribution);
  const noun = title
    .toLowerCase()
    .replace(/ findings?$/, '')
    .replace(/^vulnerability$/, 'findings');

  const toggleSev = (s: string) =>
    setSevFilter((prev) => {
      const n = new Set(prev);
      if (n.has(s)) n.delete(s);
      else n.add(s);
      return n;
    });
  const setOnlySev = (s: string) => setSevFilter(new Set([s]));
  const clearFilters = () => setSevFilter(new Set());

  const pill = (): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    height: 30,
    padding: '0 11px',
    borderRadius: 7,
    border: '1px solid var(--border2)',
    color: 'var(--text2)',
    fontSize: 12.5,
  });

  const gbTab = (g: typeof group) => ({
    height: 25,
    padding: '0 10px',
    borderRadius: 6,
    background: group === g ? 'var(--accent)' : 'var(--surface2)',
    color: group === g ? '#06231f' : 'var(--text2)',
    fontSize: 12,
    display: 'flex',
    alignItems: 'center',
    cursor: 'pointer',
  });

  return (
    <div style={{ padding: '18px 22px 40px' }}>
      {/* HEADER */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
        <span style={{ color: 'var(--text3)', display: 'flex' }}>
          <svg
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.8}
          >
            <path d="M12 7a5 5 0 015 5v3a5 5 0 01-10 0v-3a5 5 0 015-5zM7 12H3M21 12h-4M7 16H4M20 16h-3M9 4l1.5 2.5M15 4l-1.5 2.5" />
          </svg>
        </span>
        <h1 style={{ fontSize: 21, fontWeight: 600, letterSpacing: '-0.02em', margin: 0 }}>
          {title}
        </h1>
        <div style={{ flex: 1 }}></div>
        <button
          onClick={noop}
          title="Not available yet"
          style={{
            height: 30,
            padding: '0 12px',
            borderRadius: 7,
            border: '1px solid var(--border2)',
            background: 'transparent',
            color: 'var(--text2)',
            fontFamily: 'inherit',
            fontSize: 12.5,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.8}
          >
            <path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2z"></path>
          </svg>
          Save as…
        </button>
        <button
          onClick={noop}
          title="Not available yet"
          style={{
            height: 30,
            padding: '0 12px',
            borderRadius: 7,
            border: '1px solid var(--border2)',
            background: 'transparent',
            color: 'var(--text2)',
            fontFamily: 'inherit',
            fontSize: 12.5,
            cursor: 'pointer',
          }}
        >
          Manage Rules
        </button>
        <span
          style={{ fontSize: 12, color: 'var(--text3)', fontFamily: "'IBM Plex Mono',monospace" }}
        >
          {sevFilter.size === 0
            ? `${allRows.length} results`
            : `${rows.length} of ${allRows.length}`}
        </span>
      </div>

      {/* ATTRIBUTION STRIP */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: 16,
          fontSize: 11.5,
          color: 'var(--text3)',
          fontFamily: "'IBM Plex Mono',monospace",
          flexWrap: 'wrap',
        }}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--accent)"
            strokeWidth={2}
          >
            <path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z"></path>
          </svg>
          Discovered by <span style={{ color: 'var(--text2)' }}>{agent}</span>
        </span>
        {extra && <span style={{ color: 'var(--text3)' }}>{extra}</span>}
        <span style={{ color: 'var(--border2)' }}>·</span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3FB07F' }}></span>
          live
        </span>
        <span style={{ color: 'var(--border2)' }}>·</span>
        <span
          onClick={noop}
          title="Not available yet"
          style={{ color: 'var(--verified)', cursor: 'pointer' }}
        >
          audit ↗
        </span>
      </div>

      {/* LEARN BANNER */}
      {showLearn && (
        <div
          style={{
            display: 'flex',
            alignItems: 'stretch',
            gap: 0,
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            overflow: 'hidden',
            marginBottom: 14,
          }}
        >
          <div style={{ flex: 1, padding: '16px 18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
              <svg
                width="15"
                height="15"
                viewBox="0 0 24 24"
                fill="none"
                stroke="var(--accent)"
                strokeWidth={1.9}
              >
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M12 16v-4M12 8h.01"></path>
              </svg>
              <span style={{ fontSize: 13.5, fontWeight: 600 }}>Learn about {title}</span>
            </div>
            <p
              style={{
                fontSize: 12.5,
                lineHeight: 1.55,
                color: 'var(--text2)',
                margin: '0 0 12px',
                maxWidth: 620,
              }}
            >
              Findings are evidence of a specific weakness on a resource. Filter by severity,
              exploitability, and runtime validation, then route any finding to{' '}
              <span style={{ color: 'var(--verified)', fontWeight: 500 }}>Cure</span> for a signed,
              auditable remediation. Each action is recorded in the Audit Chain.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <button
                onClick={() => setShowLearn(false)}
                style={{
                  height: 28,
                  padding: '0 13px',
                  borderRadius: 7,
                  border: 'none',
                  background: 'var(--accent)',
                  color: '#06231f',
                  fontFamily: 'inherit',
                  fontSize: 12.5,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Done
              </button>
              <span
                onClick={noop}
                title="Not available yet"
                style={{ fontSize: 12, color: 'var(--accent)', cursor: 'pointer' }}
              >
                Read the docs ↗
              </span>
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: 12,
                  color: 'var(--text3)',
                  cursor: 'pointer',
                }}
              >
                <span
                  style={{
                    width: 14,
                    height: 14,
                    borderRadius: 4,
                    border: '1px solid var(--border2)',
                    display: 'inline-block',
                  }}
                ></span>
                Show help tips on new pages
              </label>
            </div>
          </div>
          <div
            onClick={noop}
            title="Not available yet"
            style={{
              width: 230,
              flex: 'none',
              position: 'relative',
              borderLeft: '1px solid var(--border)',
              background: 'linear-gradient(135deg,rgba(43,179,188,0.12),rgba(110,116,255,0.08))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
            }}
          >
            <div
              style={{
                position: 'absolute',
                top: 10,
                left: 12,
                fontFamily: "'IBM Plex Mono',monospace",
                fontSize: 9.5,
                letterSpacing: '0.08em',
                color: 'var(--text2)',
              }}
            >
              PAGE TOUR · 1:24
            </div>
            <div
              style={{
                width: 46,
                height: 46,
                borderRadius: '50%',
                background: 'var(--bg)',
                border: '1px solid var(--border2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="var(--accent)" stroke="none">
                <path d="M7 4v16l13-8z"></path>
              </svg>
            </div>
          </div>
        </div>
      )}

      {/* FILTER BAR */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
          marginBottom: 10,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            height: 30,
            padding: '0 11px',
            borderRadius: 7,
            border: '1px solid rgba(43,179,188,0.5)',
            background: 'rgba(43,179,188,0.1)',
            color: 'var(--accent)',
            fontSize: 12.5,
            fontWeight: 500,
          }}
        >
          Status: Unresolved {caretDown('currentColor')}
        </div>
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setSevMenuOpen((v) => !v)}
            style={{
              ...pill(),
              cursor: 'pointer',
              fontFamily: 'inherit',
              background: 'transparent',
            }}
          >
            Severity
            {sevFilter.size > 0 && (
              <span
                style={{
                  fontFamily: "'IBM Plex Mono',monospace",
                  fontSize: 10,
                  background: 'var(--accent)',
                  color: '#06231f',
                  borderRadius: 999,
                  padding: '1px 6px',
                  fontWeight: 700,
                }}
              >
                {sevFilter.size}
              </span>
            )}
            {caretDown('var(--text3)')}
          </button>
          {sevMenuOpen && (
            <div
              style={{
                position: 'absolute',
                top: 36,
                left: 0,
                width: 204,
                background: 'var(--surface)',
                border: '1px solid var(--border2)',
                borderRadius: 10,
                boxShadow: '0 16px 44px rgba(0,0,0,0.4)',
                zIndex: 30,
                padding: 6,
              }}
            >
              {SEV_ORDER.map((s) => {
                const on = sevFilter.has(s);
                const meta = SEV[s];
                if (!meta) return null;
                return (
                  <div
                    key={s}
                    onClick={() => toggleSev(s)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 9,
                      padding: '7px 8px',
                      borderRadius: 7,
                      cursor: 'pointer',
                      fontSize: 12.5,
                    }}
                  >
                    <span
                      style={{
                        width: 15,
                        height: 15,
                        borderRadius: 4,
                        border: `1.5px solid ${meta.fg}`,
                        background: on ? meta.fg : 'transparent',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    ></span>
                    <span
                      style={{
                        width: 18,
                        height: 18,
                        borderRadius: 5,
                        background: meta.bg,
                        color: meta.fg,
                        fontSize: 10,
                        fontWeight: 700,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontFamily: "'IBM Plex Mono',monospace",
                      }}
                    >
                      {meta.l}
                    </span>
                    <span style={{ color: 'var(--text)' }}>{s}</span>
                  </div>
                );
              })}
              <div style={{ height: 1, background: 'var(--border)', margin: '5px 4px' }}></div>
              <div
                onClick={clearFilters}
                style={{
                  padding: '6px 8px',
                  fontSize: 12,
                  color: 'var(--accent)',
                  cursor: 'pointer',
                }}
              >
                Clear all
              </div>
            </div>
          )}
        </div>
        <div style={pill()} title="Not available yet">
          Resource Type {caretDown('var(--text3)')}
        </div>
        <div style={pill()} title="Not available yet">
          Subscription {caretDown('var(--text3)')}
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            height: 30,
            padding: '0 11px',
            borderRadius: 7,
            border: '1px dashed var(--border2)',
            color: 'var(--text3)',
            fontSize: 12.5,
            cursor: 'pointer',
          }}
          onClick={noop}
          title="Not available yet"
        >
          + Filter
        </div>
      </div>

      {/* GROUP BY TABS */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <span
          style={{
            fontFamily: "'IBM Plex Mono',monospace",
            fontSize: 10,
            letterSpacing: '0.08em',
            color: 'var(--text3)',
          }}
        >
          GROUP BY
        </span>
        <div style={{ display: 'flex', gap: 5 }}>
          <div onClick={() => setGroup('rule')} style={gbTab('rule')}>
            Rule
          </div>
          <div onClick={() => setGroup('resource')} style={gbTab('resource')}>
            Resource
          </div>
          {/* decorative no-op: gbTab('subscription') is never active because `group` is never set to it */}
          <div onClick={noop} style={gbTab('subscription')} title="Not available yet">
            Subscription
          </div>
          <div onClick={() => setGroup('severity')} style={gbTab('severity')}>
            Severity
          </div>
        </div>
      </div>

      {/* SUMMARY WIDGETS */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '0.9fr 1.15fr 1.15fr',
          gap: 12,
          marginBottom: 14,
        }}
      >
        <div
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 11,
            padding: '14px 16px',
          }}
        >
          <div style={{ fontSize: 12, color: 'var(--text2)', fontWeight: 500, marginBottom: 12 }}>
            By Severity
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {SEV_ORDER.map((s) => (
              <div
                key={s}
                data-testid={`sev-filter-${s}`}
                onClick={() => setOnlySev(s)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 9,
                  cursor: 'pointer',
                  borderRadius: 6,
                  padding: '3px 5px',
                  margin: '0 -5px',
                }}
              >
                <span
                  style={{ width: 3, height: 20, borderRadius: 2, background: SEV[s]?.bar }}
                ></span>
                <span
                  style={{ fontFamily: "'IBM Plex Mono',monospace", fontSize: 16, fontWeight: 600 }}
                >
                  {sevCounts[s] ?? 0}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text3)' }}>{s}</span>
              </div>
            ))}
          </div>
        </div>
        <div
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 11,
            padding: '14px 16px',
          }}
        >
          <div style={{ fontSize: 12, color: 'var(--text2)', fontWeight: 500, marginBottom: 12 }}>
            Top by Rule
          </div>
          {widgetA.map(([label, v]) => (
            <div
              key={label}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12.5,
                marginBottom: 9,
              }}
            >
              <span
                style={{
                  fontFamily: "'IBM Plex Mono',monospace",
                  color: 'var(--text2)',
                  flex: 1,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {label}
              </span>
              <span style={{ fontFamily: "'IBM Plex Mono',monospace", color: 'var(--text3)' }}>
                {v}
              </span>
            </div>
          ))}
        </div>
        <div
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 11,
            padding: '14px 16px',
          }}
        >
          <div style={{ fontSize: 12, color: 'var(--text2)', fontWeight: 500, marginBottom: 12 }}>
            Top Resources
          </div>
          {widgetB.map(([label, v]) => (
            <div
              key={label}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12.5,
                marginBottom: 9,
              }}
            >
              <span
                style={{
                  fontFamily: "'IBM Plex Mono',monospace",
                  color: 'var(--text2)',
                  flex: 1,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {label}
              </span>
              <span style={{ fontFamily: "'IBM Plex Mono',monospace", color: 'var(--text3)' }}>
                {v}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* TABLE */}
      <div
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 11,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'flex',
            padding: '0 16px',
            height: 38,
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
          {columns.map((c) => (
            <span key={c.key} style={{ flex: c.fb ?? 1, minWidth: 0 }}>
              {c.label}
            </span>
          ))}
          <span style={{ flex: '0 0 26px' }}></span>
        </div>

        {state.status === 'loading' && (
          <div
            style={{
              padding: '40px 16px',
              textAlign: 'center',
              color: 'var(--text3)',
              fontSize: 12.5,
            }}
          >
            Loading…
          </div>
        )}

        {state.status === 'error' && (
          <div
            role="alert"
            style={{
              padding: '32px 16px',
              textAlign: 'center',
              color: 'var(--text2)',
              fontSize: 12.5,
            }}
          >
            <div style={{ marginBottom: 12, color: '#E5484D' }}>
              Failed to load: {state.message}
            </div>
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

        {state.status === 'ready' && rows.length === 0 && (
          <div
            style={{
              padding: '40px 16px',
              textAlign: 'center',
              color: 'var(--text3)',
              fontSize: 12.5,
            }}
          >
            No {noun} found
          </div>
        )}

        {state.status === 'ready' &&
          rows.length > 0 &&
          (grouped
            ? groups.map((g) => (
                <div key={g.key}>
                  <div
                    onClick={() => toggleGroup(g.key)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '0 16px',
                      height: 40,
                      background: 'var(--surface2)',
                      borderBottom: '1px solid var(--border)',
                      cursor: 'pointer',
                      fontSize: 12.5,
                    }}
                  >
                    <span style={{ color: 'var(--text3)', fontSize: 11, width: 10 }}>
                      {collapsed.has(g.key) ? '▸' : '▾'}
                    </span>
                    <span
                      style={{
                        color: 'var(--text)',
                        fontWeight: 600,
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {g.key}
                    </span>
                    <span
                      style={{
                        fontFamily: "'IBM Plex Mono',monospace",
                        fontSize: 11,
                        color: 'var(--text3)',
                      }}
                    >
                      {g.count}
                    </span>
                    <div style={{ flex: 1 }}></div>
                    <span
                      style={{
                        display: 'flex',
                        gap: 7,
                        fontFamily: "'IBM Plex Mono',monospace",
                        fontSize: 11,
                      }}
                    >
                      <span style={{ color: '#E5484D' }}>{g.c}C</span>
                      <span style={{ color: '#F2820D' }}>{g.h}H</span>
                      <span style={{ color: '#D9A40B' }}>{g.m}M</span>
                      <span style={{ color: '#4C8DFF' }}>{g.l}L</span>
                    </span>
                  </div>
                  {!collapsed.has(g.key) &&
                    g.rows.map((row) => (
                      <DataRow
                        key={`${String(row.cve)}|${String(row.resource)}|${String(row.component)}`}
                        columns={columns}
                        row={row}
                        indent
                        onOpen={() => setSelected(row)}
                      />
                    ))}
                </div>
              ))
            : rows.map((row) => (
                <DataRow
                  key={`${String(row.cve)}|${String(row.resource)}|${String(row.component)}`}
                  columns={columns}
                  row={row}
                  indent={false}
                  onOpen={() => setSelected(row)}
                />
              )))}
      </div>

      {/* DETAIL DRAWER — DetailPanel owns backdrop + role="dialog" (Task 5) */}
      {selected && <DetailPanel row={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
