// apps/web/src/nexus/ListPage.cloud-resources.test.tsx
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { TenantProvider } from '../auth/TenantProvider';
import { ListPage } from './ListPage';
import type { CloudResource, Envelope } from '../api/types';

const ROWS: CloudResource[] = [
  {
    id: 'arn:aws:s3:::my-bucket',
    kind: 'S3Bucket',
    cloud: 'aws',
    is_public: true,
    region: 'us-east-1',
  },
  {
    id: 'arn:aws:ec2:us-west-2:123456789012:instance/i-0abc',
    kind: 'EC2Instance',
    cloud: 'aws',
    is_public: false,
    region: 'us-west-2',
  },
];

const env = <T,>(d: T): Envelope<T> => ({
  data: d,
  meta: { offset: null, total: null, tenant: 'dev', generated_at: 'x' },
});
const ok = (b: unknown) =>
  ({ ok: true, status: 200, json: () => Promise.resolve(b) }) as unknown as Response;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ListPage · cloud-resources', () => {
  it('renders id, kind, cloud, Public/Private, and region', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'cloud-resources' as never} />
      </TenantProvider>
    );
    // resource id renders
    expect(await screen.findByText('arn:aws:s3:::my-bucket')).toBeInTheDocument();
    // kind renders
    expect(screen.getByText('S3Bucket')).toBeInTheDocument();
    // cloud renders
    expect(screen.getAllByText('aws')[0]).toBeInTheDocument();
    // is_public → 'Public' status chip renders (header + cell both named Public)
    expect(screen.getAllByText('Public')[0]).toBeInTheDocument();
    // is_public=false → 'Private' renders
    expect(screen.getByText('Private')).toBeInTheDocument();
    // region renders
    expect(screen.getByText('us-east-1')).toBeInTheDocument();
  });

  it('clicking a row does NOT open a dialog (no cve → drawer is gated)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'cloud-resources' as never} />
      </TenantProvider>
    );
    // Wait for rows to render, then click the first data row.
    const cell = await screen.findByText('arn:aws:s3:::my-bucket');
    fireEvent.click(cell);
    // No drawer must appear — cloud-resource rows have no `cve` field.
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('renders the correct column headers and NO Severity column', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(env(ROWS))));
    render(
      <TenantProvider>
        <ListPage view={'cloud-resources' as never} />
      </TenantProvider>
    );
    await screen.findByText('arn:aws:s3:::my-bucket');
    // correct columns (Resource appears in header + filter bar, use getAllByText)
    expect(screen.getAllByText('Resource')[0]).toBeInTheDocument();
    expect(screen.getByText('Kind')).toBeInTheDocument();
    expect(screen.getByText('Cloud')).toBeInTheDocument();
    // Public appears in header + data cell
    expect(screen.getAllByText('Public')[0]).toBeInTheDocument();
    expect(screen.getByText('Region')).toBeInTheDocument();
    // The cloud-resources config has NO Severity column. Assert against the rendered DOM
    // header row only (scoped via data-testid) to avoid the filter-bar "By Severity" text.
    expect(
      within(screen.getByTestId('col-headers')).queryByText('Severity')
    ).not.toBeInTheDocument();
  });
});
