import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { AuditChain } from './AuditChain';
const ok = (b: unknown) =>
  ({ ok: true, status: 200, json: () => Promise.resolve(b) }) as unknown as Response;
const events = {
  data: [
    {
      emitted_at: '2026-07-11T09:00:00Z',
      agent_id: 'vulnerability',
      action: 'cve.recorded',
      correlation_id: 'c1',
      source: 'jsonl:/x',
    },
  ],
  meta: {},
};
const verify = {
  data: {
    valid: true,
    entries_checked: 6,
    chains_checked: 1,
    broken_at_correlation_id: null,
    broken_at_action: null,
    total_events: 6,
    complete: true,
  },
  meta: {},
};
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('AuditChain', () => {
  it('renders real events + a hash-chain verdict, NOT a signature claim', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => Promise.resolve(ok(String(url).includes('/verify') ? verify : events)))
    );
    render(
      <TenantProvider>
        <AuditChain />
      </TenantProvider>
    );
    expect(await screen.findByText('cve.recorded')).toBeInTheDocument();
    expect(screen.getByText(/hash-chained · integrity verified/i)).toBeInTheDocument();
    expect(screen.queryByText(/signature valid/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secp256k1/i)).not.toBeInTheDocument();
  });
});
