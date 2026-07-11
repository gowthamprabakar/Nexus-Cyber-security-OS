import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { AuditPage } from './AuditPage';
import type { AuditEvent, ChainStatus, Envelope } from '../api/types';

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

const VALID_CHAIN: ChainStatus = {
  valid: true,
  entries_checked: 2,
  chains_checked: 1,
  broken_at_correlation_id: null,
  broken_at_action: null,
  total_events: 2,
  complete: true,
};
const TAMPERED_CHAIN: ChainStatus = {
  valid: false,
  entries_checked: 1,
  chains_checked: 1,
  broken_at_correlation_id: 'corr-2',
  broken_at_action: 'relationship.added',
  total_events: 2,
  complete: true,
};

function envelope<T>(data: T): Envelope<T> {
  return { data, meta: { offset: null, total: null, tenant: 'dev', generated_at: 'x' } };
}
function okResponse(body: unknown): Response {
  return { ok: true, status: 200, json: () => Promise.resolve(body) } as unknown as Response;
}
function errResponse(): Response {
  return { ok: false, status: 500, json: () => Promise.resolve({}) } as unknown as Response;
}

/** The page fetches the list AND the verify verdict; route each by URL. */
function routed(rows: AuditEvent[], chain: ChainStatus) {
  return vi.fn((url: string) =>
    Promise.resolve(
      String(url).includes('/audit/verify')
        ? okResponse(envelope(chain))
        : okResponse(envelope(rows))
    )
  );
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
    vi.stubGlobal('fetch', routed(ROWS, VALID_CHAIN));
    renderPage();
    expect(await screen.findByText('entity.upserted')).toBeInTheDocument();
    expect(screen.getByText('relationship.added')).toBeInTheDocument();
    expect(screen.getByText('vulnerability')).toBeInTheDocument();
  });

  it('shows the verified chain badge', async () => {
    vi.stubGlobal('fetch', routed(ROWS, VALID_CHAIN));
    renderPage();
    expect(await screen.findByText(/Chain verified/i)).toBeInTheDocument();
  });

  it('shows a tamper badge when the chain is broken', async () => {
    vi.stubGlobal('fetch', routed(ROWS, TAMPERED_CHAIN));
    renderPage();
    expect(await screen.findByText(/Tamper detected/i)).toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    vi.stubGlobal('fetch', routed([], { ...VALID_CHAIN, entries_checked: 0, total_events: 0 }));
    renderPage();
    expect(await screen.findByText(/No audit events yet/i)).toBeInTheDocument();
  });

  it('shows an error state with a working retry; verify failure never hides the log', async () => {
    let listCalls = 0;
    const fetchMock = vi.fn((url: string) => {
      if (String(url).includes('/audit/verify')) return Promise.resolve(errResponse()); // best-effort
      listCalls += 1;
      return Promise.resolve(listCalls === 1 ? errResponse() : okResponse(envelope(ROWS)));
    });
    vi.stubGlobal('fetch', fetchMock);
    renderPage();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText('entity.upserted')).toBeInTheDocument();
  });
});
