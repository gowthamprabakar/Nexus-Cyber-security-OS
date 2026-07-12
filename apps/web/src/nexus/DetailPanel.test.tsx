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
    // 5.6.2 appears in the Overview "Fixed Version" grid field.
    expect(screen.getAllByText(/5\.6\.2/)[0]).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /close/i }));
    expect(onClose).toHaveBeenCalled();
  });

  it('Cure-readiness pill reflects a real available patch (§9 #3)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(detail)));
    render(
      <TenantProvider>
        <DetailPanel row={{ cve: 'CVE-2024-3094' }} onClose={() => {}} />
      </TenantProvider>
    );
    await screen.findByText('xz backdoor');
    // fix_version present → pill is dynamic, not the hardcoded "Tier 1 ready".
    expect(screen.getByText(/patch available/i)).toBeInTheDocument();
    expect(screen.queryByText(/tier 1 ready/i)).not.toBeInTheDocument();
  });

  it('Cure-readiness pill says mitigation-only when no fix exists (§9 #3)', async () => {
    const noFix = { ...detail, data: { ...detail.data, fix_version: '' } };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(noFix)));
    render(
      <TenantProvider>
        <DetailPanel row={{ cve: 'CVE-2024-3094' }} onClose={() => {}} />
      </TenantProvider>
    );
    await screen.findByText('xz backdoor');
    expect(screen.getByText(/mitigation only/i)).toBeInTheDocument();
  });

  it('Remediation tab shows real advice text', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(detail)));
    render(
      <TenantProvider>
        <DetailPanel row={{ cve: 'CVE-2024-3094' }} onClose={() => {}} />
      </TenantProvider>
    );
    // Wait for data to load (overview renders first)
    await screen.findByText('xz backdoor');
    // Click the Remediation tab
    fireEvent.click(screen.getByRole('tab', { name: 'Remediation' }));
    expect(screen.getByText('Upgrade xz to 5.6.2')).toBeInTheDocument();
  });
});
