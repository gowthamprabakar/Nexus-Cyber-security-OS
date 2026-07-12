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
    // SevWord was removed — 'Critical' now renders as plain text in both the chip and the
    // By-Severity widget; assert at least one occurrence is present.
    expect(screen.getAllByText('Critical')[0]).toBeInTheDocument();
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
    // Made specific to the By-Severity widget row (testid) so the chip/menu render accessible
    // plain text without the SevWord split-node hack that corrupted screen-reader output.
    fireEvent.click(screen.getByTestId('sev-filter-Critical'));
    expect(screen.queryByText('CVE-2024-0002')).not.toBeInTheDocument();
  });
  it('shows EPSS% and a KEV badge from the real fields (§9 #1)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render1();
    await screen.findByText('CVE-2024-3094');
    // epss 0.97 → "97%"; kev:true → a "KEV" badge. "KEV" appears twice: the column
    // header label + the badge on the one KEV row (the non-KEV row shows "—").
    expect(screen.getByText('97%')).toBeInTheDocument();
    expect(screen.getAllByText('KEV')).toHaveLength(2);
  });
  it('sorts findings by EPSS descending by default (§9 #6)', async () => {
    const unsorted: VulnFinding[] = [
      {
        cve_id: 'CVE-LOW',
        severity: 'HIGH',
        kev: false,
        epss: 0.1,
        resource: 'r',
        component: 'c',
        fix_version: '',
        status: 'open',
      },
      {
        cve_id: 'CVE-HIGH',
        severity: 'CRITICAL',
        kev: true,
        epss: 0.9,
        resource: 'r',
        component: 'c',
        fix_version: '',
        status: 'open',
      },
    ];
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(unsorted))));
    render1();
    const high = await screen.findByText('CVE-HIGH');
    const low = screen.getByText('CVE-LOW');
    // 0.90 must render before 0.10 despite arriving second from the API.
    expect(high.compareDocumentPosition(low) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
  it('opens the detail panel on row click', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) =>
        url.includes('/vulnerabilities/')
          ? Promise.resolve(
              ok({
                data: {
                  cve_id: 'CVE-2024-3094',
                  description: 'xz backdoor',
                  fix_version: '5.6.2',
                  severity: 'CRITICAL',
                  cwe: [],
                  affected_resources: [],
                  remediation: { tier: 'advisory', advice: 'x' },
                },
                meta: {},
              })
            )
          : Promise.resolve(ok(env(ROWS)))
      )
    );
    render1();
    fireEvent.click(await screen.findByText('CVE-2024-3094'));
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });
});
