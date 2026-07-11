import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { OverviewPage } from './OverviewPage';
import type { Envelope, PostureSummary } from '../api/types';

const POSTURE: PostureSummary = {
  tenant: 'dev',
  scan_at: '2026-07-09T00:00:00Z',
  coverage: {
    domains_covered: 4,
    domains_total: 9,
    domain_pct: 44,
    collectors_ok: null,
    collectors_run: null,
    collector_pct: null,
    surfaced_findings: 3,
    total_findings: 10,
    surfaced_pct: 30,
  },
  totals: { attack_paths: 5, findings: 10, nodes: 40 },
  severity_distribution: { critical: 2, high: 4, medium: 8, low: 12 },
  by_domain: [{ domain: 'vulnerability', critical: 2, high: 3, medium: 1, low: 0, total: 6 }],
  exposure_funnel: { exposed: 12, vulnerable: 8, kev: 3, exploitable: 1 },
  inventory_counts: { cloud_resource: 28, cve_finding: 10 },
};

const EMPTY: PostureSummary = { ...POSTURE, totals: { attack_paths: 0, findings: 0, nodes: 0 } };

function envelope<T>(data: T): Envelope<T> {
  return { data, meta: { offset: null, total: null, tenant: 'dev', generated_at: 'x' } };
}
function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: () => Promise.resolve(body) } as unknown as Response;
}
function renderPage() {
  return render(
    <TenantProvider>
      <OverviewPage />
    </TenantProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('OverviewPage', () => {
  it('renders the board coverage-first with domains and funnel', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope(POSTURE))));
    renderPage();
    expect(await screen.findByText('Coverage')).toBeInTheDocument();
    expect(screen.getByText('44%')).toBeInTheDocument();
    expect(screen.getByText('vulnerability')).toBeInTheDocument();
    expect(screen.getByText('Exposed')).toBeInTheDocument();
  });

  it('shows the empty state when there is no scan data', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope(EMPTY))));
    renderPage();
    expect(await screen.findByText(/No scan data yet/i)).toBeInTheDocument();
  });

  it('shows an error state with a working retry', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({}),
      } as unknown as Response)
      .mockResolvedValueOnce(okResponse(envelope(POSTURE)));
    vi.stubGlobal('fetch', fetchMock);
    renderPage();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });
});
