import type { CloudResource, Envelope } from './types';

export interface CloudResourceQuery {
  offset?: number;
  limit?: number;
  kind?: string;
  public?: boolean;
}

/** Thrown on any non-2xx response so pages can render an error state. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function buildQuery(params: CloudResourceQuery): string {
  const q = new URLSearchParams();
  if (params.offset != null) q.set('offset', String(params.offset));
  if (params.limit != null) q.set('limit', String(params.limit));
  if (params.kind) q.set('kind', params.kind);
  if (params.public != null) q.set('public', String(params.public));
  const s = q.toString();
  return s ? `?${s}` : '';
}

export async function getCloudResources(
  tenant: string,
  params: CloudResourceQuery = {}
): Promise<Envelope<CloudResource[]>> {
  const res = await fetch(`/v1/inventory/cloud-resources${buildQuery(params)}`, {
    headers: { 'X-Tenant-Id': tenant },
  });
  if (!res.ok) {
    throw new ApiError(res.status, `cloud-resources request failed (${res.status})`);
  }
  return (await res.json()) as Envelope<CloudResource[]>;
}
