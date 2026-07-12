// apps/web/src/nexus/ListPage.patch.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { ListPage } from './ListPage';
import type { AvailableFix, Envelope } from '../api/types';

const ROWS: AvailableFix[] = [
  {
    component: 'log4j',
    fix_version: '2.17.1',
    cve_count: 3,
    resource_count: 12,
    max_severity: 'CRITICAL',
  },
  {
    component: 'spring-core',
    fix_version: '5.3.27',
    cve_count: 1,
    resource_count: 4,
    max_severity: 'HIGH',
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

describe('ListPage · patch', () => {
  it('renders upgrade row with counts and max-severity chip', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'patch' as never} />
      </TenantProvider>
    );
    // package name renders
    expect(await screen.findByText('log4j')).toBeInTheDocument();
    // fix version renders
    expect(screen.getByText('2.17.1')).toBeInTheDocument();
    // cve_count renders
    expect(screen.getByText('3')).toBeInTheDocument();
    // resource_count renders
    expect(screen.getByText('12')).toBeInTheDocument();
    // max_severity chip (Critical)
    expect(screen.getAllByText('Critical')[0]).toBeInTheDocument();
  });

  it('renders the correct column headers', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'patch' as never} />
      </TenantProvider>
    );
    await screen.findByText('log4j');
    expect(screen.getAllByText('Package')[0]).toBeInTheDocument();
    expect(screen.getByText('Fix version')).toBeInTheDocument();
    expect(screen.getByText('CVEs')).toBeInTheDocument();
    expect(screen.getByText('Resources')).toBeInTheDocument();
    expect(screen.getAllByText('Severity')[0]).toBeInTheDocument();
  });
});
