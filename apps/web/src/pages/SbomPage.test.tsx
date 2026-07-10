import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { SbomPage } from './SbomPage';
import type { Envelope, SbomPackage } from '../api/types';

const ROWS: SbomPackage[] = [
  { id: 'alpine:3.18#openssl', name: 'openssl', image: 'alpine:3.18', vulnerabilities: 2 },
  { id: 'alpine:3.18#zlib', name: 'zlib', image: 'alpine:3.18', vulnerabilities: 0 },
];

function envelope<T>(data: T): Envelope<T> {
  return { data, meta: { offset: null, total: null, tenant: 'dev', generated_at: 'x' } };
}
function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: () => Promise.resolve(body) } as unknown as Response;
}
function renderPage() {
  return render(
    <TenantProvider>
      <SbomPage />
    </TenantProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('SbomPage', () => {
  it('lists packages with image and vuln count', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope(ROWS))));
    renderPage();
    expect(await screen.findByText('openssl')).toBeInTheDocument();
    expect(screen.getByText('zlib')).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope([]))));
    renderPage();
    expect(await screen.findByText(/No SBOM packages yet/i)).toBeInTheDocument();
  });

  it('shows an error state with a working retry', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({}),
      } as unknown as Response)
      .mockResolvedValueOnce(okResponse(envelope(ROWS)));
    vi.stubGlobal('fetch', fetchMock);
    renderPage();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText('openssl')).toBeInTheDocument();
  });
});
