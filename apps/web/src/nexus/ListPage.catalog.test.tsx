// apps/web/src/nexus/ListPage.catalog.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { ListPage } from './ListPage';
import type { CatalogEntry, Envelope } from '../api/types';

const ROWS: CatalogEntry[] = [
  {
    cve_id: 'CVE-2024-3094',
    severity: 'CRITICAL',
    kev: true,
    epss: 0.97,
    affected_resources: 5,
  },
  {
    cve_id: 'CVE-2024-0002',
    severity: 'HIGH',
    kev: false,
    epss: null,
    affected_resources: 2,
  },
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

describe('ListPage · vuln-catalog', () => {
  it('renders CVE id, severity chip, KEV flag, and affected count', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'vuln-catalog' as never} />
      </TenantProvider>
    );
    // CVE id renders
    expect(await screen.findByText('CVE-2024-3094')).toBeInTheDocument();
    // KEV flag renders for the kev=true row (header + cell — both expected)
    expect(screen.getAllByText('KEV')[0]).toBeInTheDocument();
    // non-kev row renders dash
    expect(screen.getAllByText('—')[0]).toBeInTheDocument();
    // affected_resources count renders
    expect(screen.getByText('5')).toBeInTheDocument();
    // severity chip (Critical)
    expect(screen.getAllByText('Critical')[0]).toBeInTheDocument();
  });

  it('renders the correct column headers', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'vuln-catalog' as never} />
      </TenantProvider>
    );
    await screen.findByText('CVE-2024-3094');
    expect(screen.getAllByText('CVE')[0]).toBeInTheDocument();
    expect(screen.getAllByText('Severity')[0]).toBeInTheDocument();
    expect(screen.getAllByText('KEV')[0]).toBeInTheDocument();
    expect(screen.getByText('EPSS')).toBeInTheDocument();
    expect(screen.getByText('Affected')).toBeInTheDocument();
  });
});
