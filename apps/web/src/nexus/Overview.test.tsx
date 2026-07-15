// apps/web/src/nexus/Overview.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { Overview } from './Overview';
import type { Envelope, PostureSummary } from '../api/types';

const POSTURE: PostureSummary = {
  tenant: 'dev',
  scan_at: '2026-07-14T00:00:00Z',
  coverage: {
    domains_covered: 6,
    domains_total: 10,
    domain_pct: 60,
    collectors_ok: 8,
    collectors_run: 9,
    collector_pct: 89,
    surfaced_findings: 40,
    total_findings: 50,
    surfaced_pct: 80,
  },
  totals: { findings: 50 },
  severity_distribution: { critical: 63, high: 65, medium: 238, low: 220 },
  by_domain: [
    { domain: 'vulnerability', critical: 63, high: 65, medium: 238, low: 220, total: 586 },
  ],
  exposure_funnel: { exposed: 130, vulnerable: 84, kev: 12, exploitable: 5 },
  inventory_counts: { cloud_resource: 4812 },
};
const env = <T,>(d: T): Envelope<T> => ({
  data: d,
  meta: { offset: null, total: null, tenant: 'dev', generated_at: 'x' },
});
const ok = (b: unknown) =>
  ({ ok: true, status: 200, json: () => Promise.resolve(b) }) as unknown as Response;
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Overview board (§9 #5)', () => {
  it('renders severity distribution, exposure funnel, and coverage from /v1/posture', async () => {
    const fetchMock = vi.fn().mockResolvedValue(ok(env(POSTURE)));
    vi.stubGlobal('fetch', fetchMock);
    render(
      <TenantProvider>
        <Overview />
      </TenantProvider>
    );
    // severity distribution — real counts ("63" also appears in the by-domain row)
    expect((await screen.findAllByText('63'))[0]).toBeInTheDocument();
    expect(screen.getByText('238')).toBeInTheDocument();
    // exposure funnel — the KEV + exploitable narrowing is real
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
    // coverage surfaced pct
    expect(screen.getByText(/80%/)).toBeInTheDocument();
    // hits the real posture endpoint
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/v1/posture');
  });

  it('shows an error + retry when posture fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 500, json: () => Promise.resolve({}) })
    );
    render(
      <TenantProvider>
        <Overview />
      </TenantProvider>
    );
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });
});
