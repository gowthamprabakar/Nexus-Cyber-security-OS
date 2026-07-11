import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { VulnCatalogPage } from './VulnCatalogPage';
import type { CatalogEntry, Envelope } from '../api/types';

const ROWS: CatalogEntry[] = [
  { cve_id: 'CVE-2024-0001', severity: 'CRITICAL', kev: true, epss: 0.94, affected_resources: 12 },
  { cve_id: 'CVE-2024-0002', severity: 'HIGH', kev: false, epss: null, affected_resources: 1 },
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
      <VulnCatalogPage />
    </TenantProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('VulnCatalogPage', () => {
  it('lists unique CVEs with severity, KEV and affected count', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope(ROWS))));
    renderPage();
    expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
    expect(screen.getByText('CVE-2024-0002')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument(); // affected-resource count
  });

  it('shows the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope([]))));
    renderPage();
    expect(await screen.findByText(/No CVEs catalogued yet/i)).toBeInTheDocument();
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
    expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  });
});
