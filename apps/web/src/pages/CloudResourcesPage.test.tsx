import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { CloudResourcesPage } from './CloudResourcesPage';
import type { CloudResource, Envelope } from '../api/types';

const ROWS: CloudResource[] = [
  {
    id: 'arn:aws:ecs:us-east-1:1:svc/web',
    kind: 'ecs-service',
    cloud: 'aws',
    is_public: true,
    region: 'us-east-1',
  },
  {
    id: 'gcp:run/api',
    kind: 'gcp-cloud-run-service',
    cloud: 'gcp',
    is_public: false,
    region: null,
  },
];

function envelope(rows: CloudResource[]): Envelope<CloudResource[]> {
  return {
    data: rows,
    meta: { offset: null, total: rows.length, tenant: 'dev', generated_at: '2026-07-09T00:00:00Z' },
  };
}
function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: () => Promise.resolve(body) } as unknown as Response;
}
function errResponse(status: number): Response {
  return { ok: false, status, json: () => Promise.resolve({}) } as unknown as Response;
}
function renderPage() {
  return render(
    <TenantProvider>
      <CloudResourcesPage />
    </TenantProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CloudResourcesPage', () => {
  it('renders rows from the envelope', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope(ROWS))));
    renderPage();
    expect(await screen.findByText('arn:aws:ecs:us-east-1:1:svc/web')).toBeInTheDocument();
    expect(screen.getByText('gcp-cloud-run-service')).toBeInTheDocument();
    expect(screen.getByText('Yes')).toBeInTheDocument(); // is_public=true
    expect(screen.getByText('—')).toBeInTheDocument(); // null region
  });

  it('shows an error state with a working retry', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(errResponse(500))
      .mockResolvedValueOnce(okResponse(envelope(ROWS)));
    vi.stubGlobal('fetch', fetchMock);
    renderPage();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText('arn:aws:ecs:us-east-1:1:svc/web')).toBeInTheDocument();
  });

  it('shows the empty state when there are no rows', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope([]))));
    renderPage();
    expect(await screen.findByText(/No cloud resources yet/i)).toBeInTheDocument();
  });
});
