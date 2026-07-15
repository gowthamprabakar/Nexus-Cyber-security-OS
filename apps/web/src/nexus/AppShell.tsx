import { useState } from 'react';
import { TenantProvider } from '../auth/TenantProvider';
import { VULN_NAV, type View } from './nav';
import { ListPage } from './ListPage';
import { AuditChain } from './AuditChain';
import { Overview } from './Overview';
import { GapState } from './GapState';
import './theme.css';

const ICON_PATHS: Record<string, string> = {
  shield: 'M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z',
  board: 'M4 4h7v7H4zM13 4h7v4h-7zM13 11h7v9h-7zM4 14h7v6H4z',
  bug: 'M12 7a5 5 0 015 5v3a5 5 0 01-10 0v-3a5 5 0 015-5zM7 12H3M21 12h-4M7 16H4M20 16h-3M9 4l1.5 2.5M15 4l-1.5 2.5',
  clip: 'M9 4h6v2H9zM7 4h10v16H7zM10 10h4M10 14h4',
  box: 'M12 3 4 7v10l8 4 8-4V7zM4 7l8 4 8-4',
  cube: 'M12 3 4 7v10l8 4 8-4V7zM4 7l8 4 8-4M12 11v10',
  check: 'M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11',
  play: 'M6 4 20 12 6 20z',
  bolt: 'M13 2 4 14h7l-1 8 9-12h-7z',
  chain: 'M10 13a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1',
  doc: 'M6 2h9l5 5v15H6zM14 2v6h6',
  sun: 'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
};

function Ic({ k, size = 15 }: { k: string; size?: number }) {
  const d = ICON_PATHS[k] ?? ICON_PATHS.doc;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={d} />
    </svg>
  );
}

const LIST_VIEWS: View[] = [
  'vulnerabilities',
  'vuln-catalog',
  'kev-tracker',
  'patch',
  'sbom',
  'container-images',
  'cloud-resources',
];

function renderMain(view: View) {
  if (LIST_VIEWS.includes(view)) return <ListPage view={view} />;
  if (view === 'audit') return <AuditChain />;
  if (view === 'overview') return <Overview />;
  if (view === 'inventory-overview')
    return (
      <GapState
        needs="the inventory-overview aggregator + graph producers"
        title="Inventory Overview"
      />
    );
  if (view === 'eol') return <GapState needs="an End-of-Life producer" title="End of Life" />;
  // cure-*
  return <GapState needs="the cloud remediation engine (safety-critical)" title="Cure" />;
}

function ShellInner() {
  const [view, setView] = useState<View>('vulnerabilities');
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [bannerDismissed, setBannerDismissed] = useState(false);

  function toggleTheme() {
    const el = document.documentElement;
    el.dataset.theme = el.dataset.theme === 'light' ? '' : 'light';
  }

  return (
    <div
      style={{
        fontFamily: "'General Sans',system-ui,sans-serif",
        background: 'var(--bg)',
        color: 'var(--text)',
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        WebkitFontSmoothing: 'antialiased',
      }}
    >
      {/* TOP BAR */}
      <header
        style={{
          height: 52,
          flex: 'none',
          display: 'flex',
          alignItems: 'center',
          gap: 14,
          padding: '0 14px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--surface)',
          zIndex: 20,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, flex: 'none' }}>
          <button
            title="Collapse sidebar"
            onClick={() => setNavCollapsed((v) => !v)}
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
              strokeWidth={1.9}
            >
              <path d="M3 6h18M3 12h18M3 18h18" />
            </svg>
          </button>
          <div
            style={{
              width: 24,
              height: 24,
              borderRadius: 6,
              background: 'linear-gradient(135deg,#2BB3BC,#0C737C)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#0A0D10"
              strokeWidth={2.5}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <span style={{ fontWeight: 600, fontSize: 15, letterSpacing: '-0.01em' }}>Nexus</span>
        </div>

        <button
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            height: 30,
            padding: '0 10px',
            borderRadius: 7,
            border: '1px solid var(--border2)',
            background: 'var(--surface2)',
            color: 'var(--text)',
            fontFamily: 'inherit',
            fontSize: 13,
            cursor: 'pointer',
          }}
        >
          <svg
            width="13"
            height="13"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path d="M3 7h18M3 12h18M3 17h12" />
          </svg>
          nexus-prod
          <svg
            width="11"
            height="11"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--text3)"
            strokeWidth={2.4}
          >
            <path d="m6 9 6 6 6-6" />
          </svg>
        </button>

        <button
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            height: 30,
            padding: '0 10px',
            borderRadius: 7,
            border: '1px solid var(--border2)',
            background: 'transparent',
            color: 'var(--text2)',
            fontFamily: 'inherit',
            fontSize: 13,
            cursor: 'pointer',
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: 2,
              background: 'var(--accent)',
              display: 'inline-block',
            }}
          />
          All projects
          <svg
            width="11"
            height="11"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--text3)"
            strokeWidth={2.4}
          >
            <path d="m6 9 6 6 6-6" />
          </svg>
        </button>

        <div style={{ flex: 1 }} />

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            height: 30,
            padding: '0 10px 0 11px',
            width: 240,
            borderRadius: 7,
            border: '1px solid var(--border2)',
            background: 'var(--surface2)',
            color: 'var(--text3)',
            fontSize: 13,
            cursor: 'pointer',
          }}
        >
          <svg
            width="13"
            height="13"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
          >
            <circle cx="11" cy="11" r="7" />
            <path d="m21 21-4.3-4.3" />
          </svg>
          <span style={{ flex: 1 }}>Search…</span>
          <span
            style={{
              fontFamily: "'IBM Plex Mono',monospace",
              fontSize: 10,
              border: '1px solid var(--border2)',
              borderRadius: 4,
              padding: '1px 5px',
              color: 'var(--text2)',
            }}
          >
            ⌘K
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            height: 26,
            padding: '0 9px',
            borderRadius: 999,
            border: '1px solid rgba(139,147,255,0.4)',
            background: 'var(--verified-bg)',
            color: 'var(--verified)',
            fontSize: 12,
            fontWeight: 500,
            flex: 'none',
          }}
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" />
          </svg>
          In Trial
        </div>

        <button
          title="Toggle theme"
          onClick={toggleTheme}
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
            flex: 'none',
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
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
          </svg>
        </button>

        <button
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
            position: 'relative',
            flex: 'none',
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
            <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0" />
          </svg>
          <span
            style={{
              position: 'absolute',
              top: 4,
              right: 4,
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: '#E5484D',
            }}
          />
        </button>

        <div
          style={{
            width: 30,
            height: 30,
            borderRadius: '50%',
            background: 'linear-gradient(135deg,#3A4250,#222831)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 12,
            fontWeight: 600,
            flex: 'none',
          }}
        >
          VM
        </div>
      </header>

      {/* TRIAL BANNER */}
      {!bannerDismissed && (
        <div
          style={{
            flex: 'none',
            height: 38,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '0 16px',
            background: 'var(--verified-bg)',
            borderBottom: '1px solid rgba(139,147,255,0.25)',
            overflow: 'hidden',
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--verified)"
            strokeWidth={2}
            style={{ flex: 'none' }}
          >
            <path d="M12 2 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6z" />
          </svg>
          <span
            style={{
              fontSize: 12.5,
              color: 'var(--text)',
              fontWeight: 500,
              whiteSpace: 'nowrap',
              flex: 'none',
            }}
          >
            Nexus Cure Trial · Active
          </span>
          <span
            style={{
              fontSize: 12,
              color: 'var(--text2)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              minWidth: 0,
            }}
          >
            Agentic remediation with cryptographic audit is enabled for this environment.
          </span>
          <span
            style={{
              fontFamily: "'IBM Plex Mono',monospace",
              fontSize: 11,
              color: 'var(--text3)',
              whiteSpace: 'nowrap',
              flex: 'none',
            }}
          >
            Expires Feb 1, 2026
          </span>
          <div style={{ flex: 1, minWidth: 8 }} />
          <span
            style={{
              fontSize: 12,
              color: 'var(--verified)',
              cursor: 'pointer',
              fontWeight: 500,
              whiteSpace: 'nowrap',
              flex: 'none',
            }}
          >
            View Setup
          </span>
          <span
            style={{
              fontSize: 12,
              color: 'var(--text2)',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              flex: 'none',
            }}
          >
            Contact Account Team
          </span>
          <button
            onClick={() => setBannerDismissed(true)}
            style={{
              width: 22,
              height: 22,
              borderRadius: 6,
              border: 'none',
              background: 'transparent',
              color: 'var(--text3)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flex: 'none',
            }}
          >
            <svg
              width="13"
              height="13"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {/* SIDEBAR */}
        <nav
          style={{
            width: navCollapsed ? 52 : 222,
            flex: 'none',
            borderRight: '1px solid var(--border)',
            background: 'var(--surface)',
            overflowY: 'auto',
            overflowX: 'hidden',
            padding: '9px 8px 24px',
            display: 'flex',
            flexDirection: 'column',
            gap: 1,
            transition: 'width 0.16s ease',
          }}
        >
          {/* Persona picker */}
          <button
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 9,
              padding: 8,
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'var(--surface2)',
              color: 'var(--text)',
              cursor: 'pointer',
              fontFamily: 'inherit',
              width: '100%',
              textAlign: 'left',
              marginBottom: 6,
            }}
          >
            <span style={{ color: 'var(--accent)', flex: 'none', display: 'flex' }}>
              <Ic k="bug" />
            </span>
            {!navCollapsed && (
              <>
                <span style={{ display: 'flex', flex: 1, minWidth: 0, flexDirection: 'column' }}>
                  <span
                    style={{
                      display: 'block',
                      fontSize: 9,
                      color: 'var(--text3)',
                      fontFamily: "'IBM Plex Mono',monospace",
                      letterSpacing: '0.08em',
                    }}
                  >
                    PERSONA
                  </span>
                  <span
                    style={{
                      display: 'block',
                      fontSize: 13,
                      fontWeight: 600,
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    Vulnerability Mgmt
                  </span>
                </span>
                <svg
                  width="12"
                  height="12"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="var(--text3)"
                  strokeWidth={2.2}
                  style={{ flex: 'none' }}
                >
                  <path d="m8 9 4-4 4 4M8 15l4 4 4-4" />
                </svg>
              </>
            )}
          </button>

          {/* Nav groups */}
          {VULN_NAV.map((grp) => (
            <div key={grp.section}>
              {!navCollapsed && (
                <div
                  style={{
                    fontFamily: "'IBM Plex Mono',monospace",
                    fontSize: 10,
                    letterSpacing: '0.12em',
                    padding: '10px 8px 3px',
                    color: 'var(--text3)',
                  }}
                >
                  {grp.section.toUpperCase()}
                </div>
              )}
              {grp.items.map((item) => {
                const active = view === item.view;
                return (
                  <button
                    key={item.view}
                    title={item.label}
                    onClick={() => setView(item.view)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      justifyContent: navCollapsed ? 'center' : undefined,
                      padding: '7px 9px',
                      borderRadius: 7,
                      fontSize: 13,
                      cursor: 'pointer',
                      textDecoration: 'none',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      background: active ? 'rgba(43,179,188,0.12)' : 'transparent',
                      color: active ? 'var(--accent)' : 'var(--text2)',
                      fontWeight: active ? 600 : 400,
                      border: 'none',
                      width: '100%',
                      textAlign: 'left',
                      fontFamily: 'inherit',
                    }}
                  >
                    <span style={{ flex: 'none', display: 'flex' }}>
                      <Ic k={item.icon} />
                    </span>
                    {!navCollapsed && <span>{item.label}</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        {/* MAIN CONTENT */}
        <main style={{ flex: 1, minWidth: 0, overflowY: 'auto', position: 'relative' }}>
          {renderMain(view)}
        </main>
      </div>
    </div>
  );
}

export function AppShell() {
  return (
    <TenantProvider>
      <ShellInner />
    </TenantProvider>
  );
}
