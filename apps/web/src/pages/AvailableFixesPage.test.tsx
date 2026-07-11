import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { AvailableFixesPage } from './AvailableFixesPage';
import type { AvailableFix, Envelope } from '../api/types';

const ROWS: AvailableFix[] = [
  {
    component: 'openssl',
    fix_version: '1.1.1w',
    cve_count: 5,
    resource_count: 3,
    max_severity: 'CRITICAL',
  },
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
      <AvailableFixesPage />
    </TenantProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('AvailableFixesPage', () => {
  it('lists patch actions with impact counts', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope(ROWS))));
    renderPage();
    expect(await screen.findByText('openssl')).toBeInTheDocument();
    expect(screen.getByText('1.1.1w')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument(); // CVEs fixed
  });

  it('shows the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope([]))));
    renderPage();
    expect(await screen.findByText(/No published fixes/i)).toBeInTheDocument();
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
