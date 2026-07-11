import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { AuditPage } from './AuditPage';
import type { AuditEvent, Envelope } from '../api/types';

const ROWS: AuditEvent[] = [
  {
    emitted_at: '2026-01-01T00:00:00Z',
    agent_id: 'audit-agent',
    action: 'entity.upserted',
    correlation_id: 'corr-1',
    source: 'jsonl:/audit.jsonl',
  },
  {
    emitted_at: '2026-01-01T00:01:00Z',
    agent_id: 'vulnerability',
    action: 'relationship.added',
    correlation_id: 'corr-2',
    source: 'jsonl:/audit.jsonl',
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
      <AuditPage />
    </TenantProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('AuditPage', () => {
  it('lists audit events with agent and action', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope(ROWS))));
    renderPage();
    expect(await screen.findByText('entity.upserted')).toBeInTheDocument();
    expect(screen.getByText('relationship.added')).toBeInTheDocument();
    expect(screen.getByText('vulnerability')).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse(envelope([]))));
    renderPage();
    expect(await screen.findByText(/No audit events yet/i)).toBeInTheDocument();
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
    expect(await screen.findByText('entity.upserted')).toBeInTheDocument();
  });
});
