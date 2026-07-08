import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { VulnerabilitiesPage } from './VulnerabilitiesPage';
import type { Envelope, VulnDetail, VulnFinding } from '../api/types';

const LIST: VulnFinding[] = [
  {
    cve_id: 'CVE-2024-0001',
    severity: 'CRITICAL',
    kev: true,
    epss: 0.94,
    resource: 'img:1.0',
    component: 'openssl',
    fix_version: '1.1.1w',
    status: 'open',
  },
  {
    cve_id: 'CVE-2024-0002',
    severity: 'HIGH',
    kev: false,
    epss: null,
    resource: 'img:1.0',
    component: 'spring',
    fix_version: '',
    status: 'open',
  },
];

const DETAIL: VulnDetail = {
  cve_id: 'CVE-2024-0001',
  severity: 'CRITICAL',
  kev: true,
  epss: 0.94,
  cvss_v3_score: 9.8,
  cwe: ['CWE-120'],
  description: 'buffer overflow',
  component: 'openssl',
  fix_version: '1.1.1w',
  affected_resources: ['img:1.0'],
  first_seen: '2026-07-01T00:00:00Z',
  remediation: { tier: 'advisory', advice: 'Upgrade openssl to 1.1.1w' },
};

function envelope<T>(data: T): Envelope<T> {
  return {
    data,
    meta: { offset: null, total: null, tenant: 'dev', generated_at: '2026-07-09T00:00:00Z' },
  };
}
function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: () => Promise.resolve(body) } as unknown as Response;
}
function routedFetch(): typeof fetch {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('/vulnerabilities/CVE-2024-0001')) {
      return Promise.resolve(okResponse(envelope(DETAIL)));
    }
    return Promise.resolve(okResponse(envelope(LIST)));
  }) as unknown as typeof fetch;
}
function renderPage() {
  return render(
    <TenantProvider>
      <VulnerabilitiesPage />
    </TenantProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('VulnerabilitiesPage', () => {
  it('lists findings and opens detail on row click', async () => {
    vi.stubGlobal('fetch', routedFetch());
    renderPage();
    expect(await screen.findByText('CVE-2024-0002')).toBeInTheDocument();
    fireEvent.click(screen.getByText('CVE-2024-0001'));
    expect(await screen.findByText('buffer overflow')).toBeInTheDocument();
    expect(screen.getByText(/Upgrade openssl to 1\.1\.1w/)).toBeInTheDocument();
  });

  it('shows an error state with a working retry', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: () => Promise.resolve({}),
      } as unknown as Response)
      .mockResolvedValueOnce(okResponse(envelope(LIST)));
    vi.stubGlobal('fetch', fetchMock);
    renderPage();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText('CVE-2024-0002')).toBeInTheDocument();
  });

  it('shows the empty state when there are no findings', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope([]))));
    renderPage();
    expect(await screen.findByText(/No vulnerabilities found/i)).toBeInTheDocument();
  });
});
