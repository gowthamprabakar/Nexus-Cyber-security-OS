// apps/web/src/nexus/ListPage.container-images.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { ListPage } from './ListPage';
import type { ContainerImage, Envelope } from '../api/types';

const ROWS: ContainerImage[] = [
  {
    id: 'docker.io/myapp:1.2.3',
    packages: 42,
    vulnerabilities: 7,
  },
  {
    id: 'gcr.io/project/api:latest',
    packages: 18,
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

describe('ListPage · container-images', () => {
  it('renders image id, packages count, and vulnerabilities count', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'container-images' as never} />
      </TenantProvider>
    );
    // image id renders
    expect(await screen.findByText('docker.io/myapp:1.2.3')).toBeInTheDocument();
    // packages count renders
    expect(screen.getByText('42')).toBeInTheDocument();
    // vulnerabilities count renders
    expect(screen.getByText('7')).toBeInTheDocument();
  });

  it('renders the correct column headers and NOT the wrong (findings) columns', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'container-images' as never} />
      </TenantProvider>
    );
    await screen.findByText('docker.io/myapp:1.2.3');
    // correct columns
    expect(screen.getByText('Image')).toBeInTheDocument();
    expect(screen.getByText('Packages')).toBeInTheDocument();
    expect(screen.getByText('Vulnerabilities')).toBeInTheDocument();
    // wrong (findings) columns must NOT appear
    expect(screen.queryByText('Component')).not.toBeInTheDocument();
    expect(screen.queryByText('Fix')).not.toBeInTheDocument();
  });
});
