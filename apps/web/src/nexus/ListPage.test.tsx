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
