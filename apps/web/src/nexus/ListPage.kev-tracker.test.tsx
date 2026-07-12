// apps/web/src/nexus/ListPage.kev-tracker.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { ListPage } from './ListPage';
import type { CatalogEntry, Envelope } from '../api/types';

// KEV Tracker = the catalog filtered to CISA Known-Exploited CVEs (§9 #4).
const ROWS: CatalogEntry[] = [
  { cve_id: 'CVE-2024-3094', severity: 'CRITICAL', kev: true, epss: 0.97, affected_resources: 5 },
  { cve_id: 'CVE-2021-44228', severity: 'CRITICAL', kev: true, epss: 0.94, affected_resources: 8 },
];
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

describe('ListPage · kev-tracker', () => {
  it('fetches the catalog filtered to KEV and renders the board (§9 #4)', async () => {
    const fetchMock = vi.fn().mockResolvedValue(ok(env(ROWS)));
    vi.stubGlobal('fetch', fetchMock);
    render(
      <TenantProvider>
        <ListPage view={'kev-tracker' as never} />
      </TenantProvider>
    );
    expect(await screen.findByText('KEV Tracker')).toBeInTheDocument();
    expect(screen.getByText('CVE-2024-3094')).toBeInTheDocument();
    // real EPSS rendered as a whole percent
    expect(screen.getByText('97%')).toBeInTheDocument();
    // the request is scoped to KEV so noise never reaches this board
    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toContain('/v1/findings/catalog');
    expect(url).toContain('kev=true');
  });
});
