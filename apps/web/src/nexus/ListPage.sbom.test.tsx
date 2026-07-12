// apps/web/src/nexus/ListPage.sbom.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { ListPage } from './ListPage';
import type { Envelope, SbomPackage } from '../api/types';

const ROWS: SbomPackage[] = [
  {
    id: 'pkg:npm/lodash@4.17.20',
    name: 'lodash',
    image: 'myapp:latest',
    vulnerabilities: 2,
  },
  {
    id: 'pkg:npm/express@4.18.0',
    name: 'express',
    image: 'myapp:latest',
    vulnerabilities: 0,
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

describe('ListPage · sbom', () => {
  it('renders package name, image, and vuln count', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'sbom' as never} />
      </TenantProvider>
    );
    // package name renders
    expect(await screen.findByText('lodash')).toBeInTheDocument();
    // image renders
    expect(screen.getAllByText('myapp:latest')[0]).toBeInTheDocument();
    // vuln count renders
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('renders the correct column headers', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'sbom' as never} />
      </TenantProvider>
    );
    await screen.findByText('lodash');
    expect(screen.getByText('Package')).toBeInTheDocument();
    expect(screen.getByText('Image')).toBeInTheDocument();
    expect(screen.getByText('Vulnerabilities')).toBeInTheDocument();
  });
});
