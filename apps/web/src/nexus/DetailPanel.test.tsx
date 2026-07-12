// apps/web/src/nexus/DetailPanel.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { DetailPanel } from './DetailPanel';

const ok = (b: unknown) =>
  ({ ok: true, status: 200, json: () => Promise.resolve(b) }) as unknown as Response;
const detail = {
  data: {
    cve_id: 'CVE-2024-3094',
    severity: 'CRITICAL',
    kev: true,
    epss: 0.97,
    cvss_v3_score: 10,
    cwe: ['CWE-506'],
    description: 'xz backdoor',
    component: 'xz',
    fix_version: '5.6.2',
    affected_resources: ['api:1'],
    remediation: { tier: 'advisory', advice: 'Upgrade xz to 5.6.2' },
  },
  meta: {},
};
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('DetailPanel', () => {
  it('shows real per-CVE detail and closes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(detail)));
    const onClose = vi.fn();
    render(
      <TenantProvider>
        <DetailPanel row={{ cve: 'CVE-2024-3094' }} onClose={onClose} />
      </TenantProvider>
    );
    expect(await screen.findByText('xz backdoor')).toBeInTheDocument();
    // 5.6.2 legitimately appears in both the "Fixed Version" grid field and the remediation advice.
    expect(screen.getAllByText(/5\.6\.2/)[0]).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
