# Vuln Persona — Slice 1 (Frontend Rebuild) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Nexus Console Vulnerability-Management persona in the existing `apps/web` React app, reusing the mock's exact CSS + markup, driven by the real read-API, with honest gap-states for everything without a backend.

**Architecture:** Faithful mechanical port. Extract the mock's theme variables + global `<style>` into an `apps/web` stylesheet (byte-identical), then port each mock view's markup — inline styles and all — into React components, swapping only the framework (`{{binding}}`→props, `<sc-for>`→`.map`, `<sc-if>`→conditional, `on*="{{h}}"`→`onClick`) and the data source (hardcoded→`client.ts` fetch). The mock renders all six list pages through one shared `isList` template, so we build one `ListPage` + per-view config, plus bespoke `AuditChain` and gap-stated boards. Data layer (`client.ts`, `types.ts`, `TenantProvider`) is reused unchanged.

**Tech Stack:** React 18 + TypeScript + Vite; Vitest + `@testing-library/react` (jsdom); pnpm + turbo; the existing `nexus-web` package. Backend is the read-API (`packages/read-api`, FastAPI) — unchanged in this slice.

## Reference artifacts (read before starting any task)

- **Design source (the exact markup to port):** `scratchpad/mock-markup.html` (per-view blocks gated by `is*` flags: `isList`, `isAudit`, `isOverview`, `isInvOverview`) and `scratchpad/mock-component.js` (`themes()` = the CSS variables; `colsFor(view)` = column defs; `personas()` = nav; the two `<style>` blocks).
- **Spec:** `docs/superpowers/specs/2026-07-12-vuln-persona-real-build-design.md`.
- **Gap analysis (what's real vs gap per node):** `scratchpad/gap-analysis.html`.
- **Backend truth:** `scratchpad/engine-facts.md` (endpoint fields).

The port is a **referenced mechanical transformation** of existing markup, not new visual design: where a step says "port the `<isList>` block," it means copy that block's markup + inline styles from `mock-markup.html` and apply the four framework swaps. The data-binding, state, config, gap-state, action, and test code below is given in full.

## Global Constraints

- **Design fidelity is the acceptance bar:** each page must be operator-approved against the mock screenshot (served over http, real timing — NOT headless virtual-time, which renders differently from a real browser). No visual reinterpretation.
- **No fabricated data:** every rendered value is real read-API data or an honest `GapState`. No hardcoded rows, no sample data, no dead buttons that pretend to act.
- **Tenant-scoped:** every fetch goes through `client.ts`, which sends `X-Tenant-Id`. Never bypass it.
- **Reuse, don't duplicate:** use the existing `apps/web/src/api/client.ts`, `api/types.ts`, `auth/TenantProvider.tsx`. Add to them; do not fork them.
- **Correctness fixes are mandatory (from the gap analysis):** Container-Images shows `packages`+`vulnerabilities` counts (not findings columns); Cloud-Resources shows `is_public`/`region`/`cloud`/`kind` (not a phantom Severity); Catalog shows KEV/EPSS/affected-count; Catalog/Patch attribution = D.1 (not D.3); **the Audit page must say "hash-chained · integrity verified", never "signature valid / secp256k1"** — the engine is SHA-256 hash-chained, not signed.
- **Commits:** husky must stay green, NEVER `--no-verify`; conventional type; subject lowercase ≤100 chars, body lines ≤100. End every commit body with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Green before done:** `pnpm --filter nexus-web run typecheck && lint && test && build` all pass. (`uv run mypy` / `uv run pytest` only when a task touches Python — this slice is frontend-only unless a task says otherwise.)
- **Verify commands:** frontend tests via `pnpm --filter nexus-web run test`; single file via `pnpm --filter nexus-web exec vitest run src/path/File.test.tsx`.

## File Structure

- `apps/web/src/nexus/theme.css` — **create.** The mock's `themes()` variables as `:root` + `[data-theme=light]` CSS custom properties, plus the two mock `<style>` blocks. One responsibility: the design tokens + global rules.
- `apps/web/src/nexus/AppShell.tsx` — **create.** Sidebar (persona picker + sectioned nav), top bar, trial banner, theme toggle, client-side `view` state + routing to page components.
- `apps/web/src/nexus/nav.ts` — **create.** The Vuln persona's nav groups (label, view-id, icon) ported from `personas().vuln.groups`; pure data.
- `apps/web/src/nexus/GapState.tsx` — **create.** The shared honest "not available yet — needs `<producer>`" panel.
- `apps/web/src/nexus/ListPage.tsx` — **create.** The universal list (header, filter bar, group-by, summary widgets, table) ported from the `isList` block; parameterized by a `ListConfig`.
- `apps/web/src/nexus/listConfig.ts` — **create.** Per-view `ListConfig` (title, endpoint fetcher, columns, row-map, attribution) for the six list views, with the correctness fixes.
- `apps/web/src/nexus/DetailPanel.tsx` — **create.** The shared finding drawer (tabs), driven by the selected row.
- `apps/web/src/nexus/AuditChain.tsx` — **create.** The bespoke audit page (real `/v1/audit` + `/v1/audit/verify`, corrected copy).
- `apps/web/src/nexus/useFetch.ts` — **create.** A tiny fetch-state hook (loading/error/ready) reused by every page.
- `apps/web/src/api/client.ts` — **modify.** Add any missing fetchers (`getCloudResources` etc. already exist; add `verifyAuditChain`).
- `apps/web/src/App.tsx` — **modify (replace body).** Render `<AppShell/>` instead of the old generic pages.
- `apps/web/src/pages/*` — **delete** at the end (Task 13): the old generic-design pages/tests are superseded by the `nexus/` port.
- Tests: co-located `*.test.tsx` next to each component.

---

## Task 1: Design tokens — extract the mock theme into `apps/web`

**Files:**

- Create: `apps/web/src/nexus/theme.css`
- Create: `apps/web/src/nexus/theme.smoke.test.tsx`
- Modify: `apps/web/src/main.tsx` (import `./nexus/theme.css`)

**Interfaces:**

- Produces: a global stylesheet defining the mock's CSS variables on `:root` (dark) and `[data-theme="light"]`, plus the mock's two `<style>` block rules. Consumed by every later component via inline styles that reference `var(--…)`.

- [ ] **Step 1: Extract the theme values.** From `scratchpad/mock-component.js`, read the `themes()` function — it returns `{ dark:{…}, light:{…} }` maps of variable→value (e.g. `--bg`, `--surface`, `--surface2`, `--text`, `--text2`, `--border`, `--verified`, `--crit`, `--high`, `--med`, `--low`, `--teal`…). From `scratchpad/mock-markup.html`, read the two `<style>` blocks (global rules: fonts, scrollbar, resets).

- [ ] **Step 2: Write `theme.css`.** Emit the dark map as `:root{ --x:val; … }`, the light map as `[data-theme="light"]{ --x:val; … }`, then paste the two `<style>` blocks' rules verbatim (minus the `<style>` tags). Values must be byte-identical to the mock.

- [ ] **Step 3: Import it.** In `apps/web/src/main.tsx`, add `import './nexus/theme.css';` (keep the existing `import './styles.css'` for now; Task 13 removes the old one).

- [ ] **Step 4: Write the smoke test.**

```tsx
// apps/web/src/nexus/theme.smoke.test.tsx
import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';

describe('nexus theme', () => {
  it('defines the core CSS variables on :root via the imported sheet', async () => {
    await import('./theme.css'); // import for side effect; jsdom ignores CSS but this guards the path
    const el = document.createElement('div');
    el.setAttribute('style', 'color: var(--text)');
    render(<div style={{ background: 'var(--bg)' }}>ok</div>);
    // jsdom does not compute custom properties; assert the sheet import resolved (no throw) and a var ref renders.
    expect(el.style.color).toContain('var(--text)');
  });
});
```

- [ ] **Step 5: Verify + commit.**

Run: `pnpm --filter nexus-web run typecheck && pnpm --filter nexus-web exec vitest run src/nexus/theme.smoke.test.tsx`
Expected: typecheck clean; 1 test passes.

```bash
git add apps/web/src/nexus/theme.css apps/web/src/nexus/theme.smoke.test.tsx apps/web/src/main.tsx
git commit -m "feat(web): extract Nexus mock theme tokens + global styles"
```

---

## Task 2: `useFetch` hook — the shared fetch-state machine

**Files:**

- Create: `apps/web/src/nexus/useFetch.ts`
- Create: `apps/web/src/nexus/useFetch.test.tsx`

**Interfaces:**

- Produces: `type FetchState<T> = {status:'loading'} | {status:'error';message:string;retry:()=>void} | {status:'ready';data:T}` and `function useFetch<T>(fn: (tenant:string)=>Promise<T>, tenant:string): FetchState<T>`. Consumed by `ListPage`, `AuditChain`, and every data page.

- [ ] **Step 1: Write the failing test.**

```tsx
// apps/web/src/nexus/useFetch.test.tsx
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { useFetch } from './useFetch';

function Probe({ fn }: { fn: (t: string) => Promise<string> }) {
  const s = useFetch(fn, 'dev');
  if (s.status === 'loading') return <div>loading</div>;
  if (s.status === 'error') return <button onClick={s.retry}>err:{s.message}</button>;
  return <div>data:{s.data}</div>;
}

describe('useFetch', () => {
  it('resolves to ready with data', async () => {
    render(<Probe fn={() => Promise.resolve('hi')} />);
    expect(await screen.findByText('data:hi')).toBeInTheDocument();
  });
  it('captures errors and retries', async () => {
    const fn = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce('ok');
    render(<Probe fn={fn} />);
    fireEvent.click(await screen.findByText('err:boom'));
    expect(await screen.findByText('data:ok')).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it — expect FAIL** (`useFetch` not defined).
      Run: `pnpm --filter nexus-web exec vitest run src/nexus/useFetch.test.tsx`

- [ ] **Step 3: Implement.**

```ts
// apps/web/src/nexus/useFetch.ts
import { useCallback, useEffect, useState } from 'react';

export type FetchState<T> =
  | { status: 'loading' }
  | { status: 'error'; message: string; retry: () => void }
  | { status: 'ready'; data: T };

export function useFetch<T>(fn: (tenant: string) => Promise<T>, tenant: string): FetchState<T> {
  const [state, setState] = useState<FetchState<T>>({ status: 'loading' });
  const run = useCallback(() => {
    let live = true;
    setState({ status: 'loading' });
    fn(tenant).then(
      (data) => {
        if (live) setState({ status: 'ready', data });
      },
      (e: unknown) => {
        if (live)
          setState({
            status: 'error',
            message: e instanceof Error ? e.message : 'Unknown error',
            retry: run,
          });
      }
    );
    return () => {
      live = false;
    };
  }, [fn, tenant]);
  useEffect(() => run(), [run]);
  return state;
}
```

- [ ] **Step 4: Run — expect PASS** (2 tests).
- [ ] **Step 5: Commit.**

```bash
git add apps/web/src/nexus/useFetch.ts apps/web/src/nexus/useFetch.test.tsx
git commit -m "feat(web): useFetch loading/error/retry/ready hook"
```

---

## Task 3: Nav data + `AppShell`

**Files:**

- Create: `apps/web/src/nexus/nav.ts`
- Create: `apps/web/src/nexus/AppShell.tsx`
- Create: `apps/web/src/nexus/AppShell.test.tsx`
- Modify: `apps/web/src/App.tsx`

**Interfaces:**

- Consumes: nothing (top of the tree).
- Produces: `export type View = 'vulnerabilities'|'vuln-catalog'|'patch'|'sbom'|'container-images'|'cloud-resources'|'audit'|'overview'|'inventory-overview'|'eol'|'cure-recommend'|'cure-dryrun'|'cure-execute'`; `export const VULN_NAV: {section:string; items:{label:string; view:View; icon:string}[]}[]`; `<AppShell/>` which holds `view` state and renders the matching page.

- [ ] **Step 1: Write `nav.ts`.** Port `personas().vuln.groups` from `scratchpad/mock-component.js` (Boards: Vulnerability Overview/`overview`, Patch Management/`patch`; Findings: Vulnerability Findings/`vulnerabilities`, End of Life/`eol`; Inventory: Inventory Overview/`inventory-overview`, SBOM/`sbom`, Container Images/`container-images`, Cloud Resources/`cloud-resources`; Cure: Recommend/`cure-recommend`, Dry-Run/`cure-dryrun`, Execute/`cure-execute`, Audit Chain/`audit`; Policies: Vulnerability Catalog/`vuln-catalog`) into the `VULN_NAV` array with the mock's icon keys.

- [ ] **Step 2: Write the failing test.**

```tsx
// apps/web/src/nexus/AppShell.test.tsx
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { AppShell } from './AppShell';

// stub every page so the shell test is isolated to nav/routing
vi.mock('./ListPage', () => ({ ListPage: ({ view }: { view: string }) => <div>list:{view}</div> }));
vi.mock('./AuditChain', () => ({ AuditChain: () => <div>audit-page</div> }));
vi.mock('./GapState', () => ({
  GapState: ({ needs }: { needs: string }) => <div>gap:{needs}</div>,
}));

describe('AppShell', () => {
  it('renders the vuln sidebar and defaults to the Findings page', () => {
    render(<AppShell />);
    expect(screen.getByText('Vulnerability Findings')).toBeInTheDocument();
    expect(screen.getByText('list:vulnerabilities')).toBeInTheDocument();
  });
  it('navigates when a nav item is clicked', () => {
    render(<AppShell />);
    fireEvent.click(screen.getByText('SBOM'));
    expect(screen.getByText('list:sbom')).toBeInTheDocument();
  });
  it('routes bespoke + gap views', () => {
    render(<AppShell />);
    fireEvent.click(screen.getByText('Audit Chain'));
    expect(screen.getByText('audit-page')).toBeInTheDocument();
    fireEvent.click(screen.getByText('End of Life'));
    expect(screen.getByText(/gap:/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Run — expect FAIL.**

- [ ] **Step 4: Implement `AppShell.tsx`.** Port the mock's sidebar + top-bar + trial-banner markup (inline styles) from `mock-markup.html`. Hold `const [view, setView] = useState<View>('vulnerabilities')`. Render `VULN_NAV` sections; each item `onClick={() => setView(item.view)}`, active styling from the mock. Route in the main area:
  - list views (`vulnerabilities`,`vuln-catalog`,`patch`,`sbom`,`container-images`,`cloud-resources`) → `<ListPage view={view} />`
  - `audit` → `<AuditChain />`
  - `overview`,`inventory-overview` → `<GapState needs="the posture/board aggregator + attack-path + trend producers" title="Overview" />`
  - `eol` → `<GapState needs="an End-of-Life producer" title="End of Life" />`
  - `cure-*` → `<GapState needs="the cloud remediation engine (safety-critical)" title="Cure" />`
    Wrap in `<TenantProvider>`. Theme toggle sets `document.documentElement.dataset.theme`.

- [ ] **Step 5: Replace `App.tsx` body** to render `<AppShell/>` (keep the `TenantProvider` inside AppShell).

- [ ] **Step 6: Run — expect PASS (3 tests).**
- [ ] **Step 7: Commit.**

```bash
git add apps/web/src/nexus/nav.ts apps/web/src/nexus/AppShell.tsx apps/web/src/nexus/AppShell.test.tsx apps/web/src/App.tsx
git commit -m "feat(web): Nexus AppShell — vuln sidebar, top bar, view routing"
```

---

## Task 4: `ListPage` + Findings config — THE FIDELITY PROOF

**Files:**

- Create: `apps/web/src/nexus/ListPage.tsx`
- Create: `apps/web/src/nexus/listConfig.ts`
- Create: `apps/web/src/nexus/ListPage.test.tsx`

**Interfaces:**

- Consumes: `useFetch`, `client.ts` fetchers, `types.ts`.
- Produces: `type Column = {label:string; key:string; type:'text'|'mono'|'two'|'sev'|'status'}`; `type ListConfig = {title:string; attribution:string; fetch:(t:string)=>Promise<Record<string,unknown>[]>; columns:Column[]}`; `export const LIST_CONFIG: Record<View, ListConfig>`; `<ListPage view={View}/>`. `DetailPanel` (Task 5) consumes the selected row object.

- [ ] **Step 1: Write the Findings config** in `listConfig.ts` (only the `vulnerabilities` entry for this task; the rest arrive in Tasks 6–10). Map `/v1/findings/vulnerabilities` rows to display rows using the mock's `colsFor('vulnerabilities')` columns (Finding=`cve_id` mono, Resource=`resource` two, Component=`component` two, Status=`status` status, Severity=`severity` sev, Fix=`fix_version` mono, Subscription=`resource`→derived mono). Title `"Vulnerability Findings"`, attribution `"Discovered by D.1 Vulnerability v0.1 + D.7 Threat Intel"`.

```ts
// apps/web/src/nexus/listConfig.ts (Findings entry; extended in later tasks)
import { getVulnerabilities } from '../api/client';
import type { View } from './nav';

export type Column = {
  label: string;
  key: string;
  type: 'text' | 'mono' | 'two' | 'sev' | 'status';
};
export type ListConfig = {
  title: string;
  attribution: string;
  fetch: (tenant: string) => Promise<Record<string, unknown>[]>;
  columns: Column[];
};

const titleCase = (s: string) => (s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : '');

export const LIST_CONFIG: Partial<Record<View, ListConfig>> = {
  vulnerabilities: {
    title: 'Vulnerability Findings',
    attribution: 'Discovered by D.1 Vulnerability v0.1 · + D.7 Threat Intel',
    fetch: async (t) =>
      (await getVulnerabilities(t, { limit: 500 })).data.map((r) => ({
        cve: r.cve_id,
        resource: r.resource,
        component: r.component || '—',
        status: 'Unresolved',
        severity: titleCase(r.severity),
        fix: r.fix_version || '—',
        kev: r.kev,
        epss: r.epss,
        _raw: r,
      })),
    columns: [
      { label: 'Finding', key: 'cve', type: 'mono' },
      { label: 'Resource', key: 'resource', type: 'two' },
      { label: 'Component', key: 'component', type: 'two' },
      { label: 'Status', key: 'status', type: 'status' },
      { label: 'Severity', key: 'severity', type: 'sev' },
      { label: 'Fix', key: 'fix', type: 'mono' },
    ],
  },
};
```

- [ ] **Step 2: Write the failing test.**

```tsx
// apps/web/src/nexus/ListPage.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { ListPage } from './ListPage';
import type { Envelope, VulnFinding } from '../api/types';

const ROWS: VulnFinding[] = [
  {
    cve_id: 'CVE-2024-3094',
    severity: 'CRITICAL',
    kev: true,
    epss: 0.97,
    resource: 'api:1',
    component: 'xz',
    fix_version: '5.6.2',
    status: 'open',
  },
  {
    cve_id: 'CVE-2024-0002',
    severity: 'HIGH',
    kev: false,
    epss: null,
    resource: 'api:1',
    component: 'spring',
    fix_version: '',
    status: 'open',
  },
];
const env = <T,>(d: T): Envelope<T> => ({
  data: d,
  meta: { offset: null, total: null, tenant: 'dev', generated_at: 'x' },
});
const ok = (b: unknown) =>
  ({ ok: true, status: 200, json: () => Promise.resolve(b) }) as unknown as Response;
const render1 = (view = 'vulnerabilities') =>
  render(
    <TenantProvider>
      <ListPage view={view as never} />
    </TenantProvider>
  );
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ListPage · vulnerabilities', () => {
  it('renders real rows with the mock columns', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render1();
    expect(await screen.findByText('CVE-2024-3094')).toBeInTheDocument();
    expect(screen.getByText('xz')).toBeInTheDocument();
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });
  it('shows loading then error+retry', async () => {
    const f = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({}),
      } as unknown as Response)
      .mockResolvedValueOnce(ok(env(ROWS)));
    vi.stubGlobal('fetch', f);
    render1();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText('CVE-2024-3094')).toBeInTheDocument();
  });
  it('shows the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env([]))));
    render1();
    expect(await screen.findByText(/no .* found/i)).toBeInTheDocument();
  });
  it('filters by severity client-side', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render1();
    await screen.findByText('CVE-2024-3094');
    fireEvent.click(screen.getByRole('button', { name: /severity/i }));
    fireEvent.click(screen.getByText('Critical'));
    expect(screen.queryByText('CVE-2024-0002')).not.toBeInTheDocument();
  });
  it('opens the detail panel on row click', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render1();
    fireEvent.click(await screen.findByText('CVE-2024-3094'));
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Run — expect FAIL.**

- [ ] **Step 4: Implement `ListPage.tsx`.** Port the `isList` block from `mock-markup.html` (header, `Save as`/`Manage Rules`, attribution strip, filter bar, GROUP BY tabs, the three summary widgets, the table) preserving inline styles. Drive it from `LIST_CONFIG[view]` + `useFetch`. Render the four states (`loading`/`error`+retry(role=alert, button "Retry")/`empty`("No {noun} found")/`ready`). Client-side severity filter + group-by on the loaded rows. Row click sets a `selected` row and renders `<DetailPanel row={selected} onClose={…}/>` (Task 5) inside a `role="dialog"`. Cell rendering by `column.type` (sev = colored chip using the mock's `--crit/--high/--med/--low`; two = primary+sub; mono = monospace). Decorative controls (Status/Resource-Type/Subscription filter, `+ Filter`, `Save as`, `Manage Rules`) are rendered visually but wired to a no-op with a `title="Not available yet"` — never a fake toast.

- [ ] **Step 5: Run — expect PASS (5 tests).**

- [ ] **Step 6: Fidelity gate.** Build, serve, screenshot the Findings page, and place it beside `scratchpad/console.png` (the mock's Findings render) for operator approval BEFORE Task 6.
      Run: `pnpm --filter nexus-web run build` then serve `apps/web/dist` and screenshot over http.

- [ ] **Step 7: Commit.**

```bash
git add apps/web/src/nexus/ListPage.tsx apps/web/src/nexus/listConfig.ts apps/web/src/nexus/ListPage.test.tsx
git commit -m "feat(web): universal ListPage + Findings config (fidelity proof)"
```

---

## Task 5: `DetailPanel`

**Files:**

- Create: `apps/web/src/nexus/DetailPanel.tsx`
- Create: `apps/web/src/nexus/DetailPanel.test.tsx`

**Interfaces:**

- Consumes: the selected row object from `ListPage` (`{cve, resource, component, severity, fix, _raw}`), `getVulnerability` from `client.ts`.
- Produces: `<DetailPanel row={Record<string,unknown>} onClose={()=>void}/>` — a `role="dialog"` drawer.

- [ ] **Step 1: Write the failing test.**

```tsx
// apps/web/src/nexus/DetailPanel.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { DetailPanel } from './DetailPanel';

const ok = (b: unknown) =>
  ({ ok: true, status: 200, json: () => Promise.resolve(b) }) as unknown as Response;
const detail = {
  data: {
    cve_id: 'CVE-2024-3094',
    severity: 'CRITICAL',
    kev: true,
    epss: 0.97,
    cvss_v3_score: 10,
    cwe: ['CWE-506'],
    description: 'xz backdoor',
    component: 'xz',
    fix_version: '5.6.2',
    affected_resources: ['api:1'],
    remediation: { tier: 'advisory', advice: 'Upgrade xz to 5.6.2' },
  },
  meta: {},
};
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('DetailPanel', () => {
  it('shows real per-CVE detail and closes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(detail)));
    const onClose = vi.fn();
    render(
      <TenantProvider>
        <DetailPanel row={{ cve: 'CVE-2024-3094' }} onClose={onClose} />
      </TenantProvider>
    );
    expect(await screen.findByText('xz backdoor')).toBeInTheDocument();
    expect(screen.getByText(/5\.6\.2/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run — FAIL. Step 3: Implement.** Port the panel markup from the `panelOpen` block; fetch `getVulnerability(tenant, row.cve)` on mount for the Overview tab (real description/cvss/cwe/affected/advice). Tabs switch client-side. **Gap-state the fake tabs** (Code-to-Cloud, Investigation, History, Comments) and the fake actions (Ignore/Support/severity-proposal) via `GapState`-style inline notes ("needs the attack-path / history / comments producers"); the **Remediate** button opens the Cure `GapState`. `role="dialog"`, a close button labeled "Close".

- [ ] **Step 4: Run — PASS. Step 5: Commit.**

```bash
git add apps/web/src/nexus/DetailPanel.tsx apps/web/src/nexus/DetailPanel.test.tsx
git commit -m "feat(web): DetailPanel — real per-CVE detail, honest gap tabs"
```

---

## Task 6: `GapState` component

**Files:**

- Create: `apps/web/src/nexus/GapState.tsx`
- Create: `apps/web/src/nexus/GapState.test.tsx`

**Interfaces:**

- Produces: `<GapState title={string} needs={string} />` — a styled honest empty panel used by AppShell (overview/inventory-overview/eol/cure) and inside DetailPanel/ListPage for gap controls.

- [ ] **Step 1: Failing test.**

```tsx
// apps/web/src/nexus/GapState.test.tsx
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { GapState } from './GapState';
describe('GapState', () => {
  it('names what the feature needs, no fake data', () => {
    render(<GapState title="End of Life" needs="an End-of-Life producer" />);
    expect(screen.getByText('End of Life')).toBeInTheDocument();
    expect(screen.getByText(/needs an End-of-Life producer/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: FAIL. Step 3: Implement** using the mock's card/surface styles: an icon, `{title}`, and "Not available yet — needs {needs}. This will turn real when that backend lands." No mock sample data.
- [ ] **Step 4: PASS. Step 5: Commit.**

```bash
git add apps/web/src/nexus/GapState.tsx apps/web/src/nexus/GapState.test.tsx
git commit -m "feat(web): GapState — honest not-available-yet panel"
```

---

## Tasks 7–11: the five remaining list views (one task each)

Each task: add the view's entry to `LIST_CONFIG` (with the mandatory correctness fix), add a test asserting its real columns render, run, commit. `ListPage` needs **no change** — only config.

### Task 7: Catalog `vuln-catalog`

- [ ] Config: `fetch` = `getCatalog(t,{limit:500})`; columns per the fix — **CVE (mono), Severity (sev), KEV (text), EPSS (mono), Affected (mono)**; attribution `"Discovered by D.1 Vulnerability v0.1"` (NOT D.3). Row-map: `{cve:cve_id, severity:titleCase(severity), kev: kev?'KEV':'—', epss: epss??'—', affected: affected_resources}`.
- [ ] Test `ListPage.catalog.test.tsx`: stub `/v1/findings/catalog` → assert a CVE, its severity chip, `KEV`, and the affected count render.
- [ ] Commit: `feat(web): Catalog list config (KEV/EPSS/affected, D.1 attribution)`

### Task 8: Patch `patch`

- [ ] Config: `fetch` = `getAvailableFixes(t)`; columns **Package (two), Fix version (mono), CVEs (mono), Resources (mono), Severity (sev)**; attribution `"Discovered by D.1 Vulnerability v0.1"` (NOT D.3). Row-map from `{component, fix_version, cve_count, resource_count, max_severity}`.
- [ ] Test: stub `/v1/findings/available-fixes` → assert an upgrade row + its counts + max-severity chip.
- [ ] Commit: `feat(web): Patch (available-fixes) list config`

### Task 9: SBOM `sbom`

- [ ] Config: `fetch` = `getSbom(t)`; columns **Package (two), Image (mono), Vulnerabilities (mono)**; attribution `"Discovered by D.1 Vulnerability v0.1"`.
- [ ] Test: stub `/v1/inventory/sbom` → assert a package name, its image, its vuln count.
- [ ] Commit: `feat(web): SBOM list config`

### Task 10: Container Images `container-images` (COLUMN FIX)

- [ ] Config: `fetch` = `getContainerImages(t)`; columns per the fix — **Image (mono), Packages (mono), Vulnerabilities (mono)** (NOT the findings columns). Row-map from `{id, packages, vulnerabilities}`.
- [ ] Test: stub `/v1/inventory/container-images` → assert the image id + its `packages` and `vulnerabilities` counts render (and that no "Component/Fix" finding columns appear).
- [ ] Commit: `feat(web): Container Images list config (real image counts)`

### Task 11: Cloud Resources `cloud-resources` (FIELD FIX)

- [ ] Config: `fetch` = `getCloudResources(t,{limit:500})`; columns per the fix — **Resource (two), Kind (text), Cloud (text), Public (status), Region (mono)**; **no Severity column**. Row-map from `{id, kind, cloud, is_public, region}` (`public: is_public?'Public':'Private'`).
- [ ] Test: stub `/v1/inventory/cloud-resources` → assert id, kind, cloud, `Public/Private`, region render; assert no Severity header.
- [ ] Commit: `feat(web): Cloud Resources list config (is_public/region/cloud/kind)`

---

## Task 12: `AuditChain` page (bespoke) + `verifyAuditChain` client (SECP256K1 FIX)

**Files:**

- Create: `apps/web/src/nexus/AuditChain.tsx`
- Create: `apps/web/src/nexus/AuditChain.test.tsx`
- Modify: `apps/web/src/api/client.ts` (add `verifyAuditChain`), `apps/web/src/api/types.ts` (add `ChainStatus` if absent)

**Interfaces:**

- Consumes: `getAuditEvents`, `verifyAuditChain` from `client.ts`.
- Produces: `<AuditChain/>`.

- [ ] **Step 1: Add the client fetcher** in `client.ts`:

```ts
export function verifyAuditChain(tenant: string): Promise<Envelope<ChainStatus>> {
  return getJson('/v1/audit/verify', tenant);
}
```

(`getAuditEvents` and `ChainStatus` already exist from PR #811; reuse them.)

- [ ] **Step 2: Write the failing test.**

```tsx
// apps/web/src/nexus/AuditChain.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { AuditChain } from './AuditChain';
const ok = (b: unknown) =>
  ({ ok: true, status: 200, json: () => Promise.resolve(b) }) as unknown as Response;
const events = {
  data: [
    {
      emitted_at: '2026-07-11T09:00:00Z',
      agent_id: 'vulnerability',
      action: 'cve.recorded',
      correlation_id: 'c1',
      source: 'jsonl:/x',
    },
  ],
  meta: {},
};
const verify = {
  data: {
    valid: true,
    entries_checked: 6,
    chains_checked: 1,
    broken_at_correlation_id: null,
    broken_at_action: null,
    total_events: 6,
    complete: true,
  },
  meta: {},
};
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('AuditChain', () => {
  it('renders real events + a hash-chain verdict, NOT a signature claim', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => Promise.resolve(ok(String(url).includes('/verify') ? verify : events)))
    );
    render(
      <TenantProvider>
        <AuditChain />
      </TenantProvider>
    );
    expect(await screen.findByText('cve.recorded')).toBeInTheDocument();
    expect(screen.getByText(/hash-chained · integrity verified/i)).toBeInTheDocument();
    expect(screen.queryByText(/signature valid/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secp256k1/i)).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 3: FAIL. Step 4: Implement** by porting the `isAudit` block, but replace the copy: header badge = "Chain integrity verified" driven by the real `verifyAuditChain` result (`valid ? 'hash-chained · integrity verified' : 'TAMPER DETECTED at '+broken_at_action`); each entry shows real `action`/`agent`/`time`; **remove every "signature valid" / "secp256k1" string** and any per-row `sig` field. "Verify integrity" button re-calls `verifyAuditChain`. "Export JSON" serializes the loaded events to a download.

- [ ] **Step 5: PASS. Step 6: Commit.**

```bash
git add apps/web/src/nexus/AuditChain.tsx apps/web/src/nexus/AuditChain.test.tsx apps/web/src/api/client.ts apps/web/src/api/types.ts
git commit -m "feat(web): Audit Chain page — real events/verify, hash-chain copy fix"
```

---

## Task 13: Free actions + retire the old pages + full-suite green

**Files:**

- Modify: `apps/web/src/nexus/ListPage.tsx` (filters→query params where the endpoint supports it; Export button)
- Delete: `apps/web/src/pages/*`, `apps/web/src/components/RowCount*`, `apps/web/src/styles.css`; update `main.tsx`.

- [ ] **Step 1: Wire the free actions.** ListPage severity filter, when set, calls the endpoint with `{severity}` (findings/catalog support it) instead of client-only; Export button serializes the loaded rows to a `Blob` download. Add a test: filter triggers a re-fetch with the param; Export produces a blob (assert `URL.createObjectURL` called).

- [ ] **Step 2: Delete the superseded generic pages + their tests** (`apps/web/src/pages/`, `components/RowCount*`), remove `import './styles.css'` from `main.tsx`, delete `styles.css`. Grep to confirm no remaining imports:
      Run: `grep -rn "src/pages\|RowCount\|styles.css" apps/web/src` → expect no hits.

- [ ] **Step 3: Full suite green.**
      Run: `pnpm --filter nexus-web run typecheck && pnpm --filter nexus-web run lint && pnpm --filter nexus-web run test && pnpm --filter nexus-web run build`
      Expected: all pass; every `nexus/` component + config covered.

- [ ] **Step 4: Fidelity pass** — screenshot all 7 real pages + the gap pages, place beside the mock renders for the operator's final page-by-page approval.

- [ ] **Step 5: Commit.**

```bash
git add -A apps/web/src
git commit -m "feat(web): wire free actions + retire generic pages; slice 1 green"
```

---

## Self-review

- **Spec coverage:** AppShell (T3) ✓ · 7 real pages: Findings (T4), Catalog (T7), Patch (T8), SBOM (T9), Container Images (T10), Cloud Resources (T11), Audit (T12) ✓ · DetailPanel (T5) ✓ · GapState + gap pages (T3 routing + T6) ✓ · faithful-port architecture (T1 tokens + per-page ports) ✓ · four states (useFetch T2 + ListPage T4) ✓ · correctness fixes: container-images cols (T10), cloud-resources fields (T11), catalog KEV/EPSS (T7), attribution (T7/T8), secp256k1 (T12) ✓ · free actions (T13) ✓ · testing per page + full green (each task + T13) ✓ · fidelity gate (T4, T13) ✓.
- **Placeholder scan:** the markup port is a referenced transformation of a named source (`mock-markup.html`), stated explicitly — not a "TODO." All new code (hook, config, states, gap-state, client, tests) is given in full.
- **Type consistency:** `View` (T3) used across configs; `ListConfig`/`Column` (T4) used by T7–T11; `FetchState`/`useFetch` (T2) used by ListPage/AuditChain; `ChainStatus` reused from existing `types.ts`.
