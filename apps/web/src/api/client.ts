import type {
  AvailableFix,
  CatalogEntry,
  CloudResource,
  ContainerImage,
  Envelope,
  PostureSummary,
  SbomPackage,
  VulnDetail,
  VulnFinding,
} from './types';

type QueryValue = string | number | boolean | undefined;

export interface CloudResourceQuery {
  offset?: number;
  limit?: number;
  kind?: string;
  public?: boolean;
}

export interface VulnQuery {
  offset?: number;
  limit?: number;
  severity?: string;
  kev?: boolean;
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

function buildQuery(entries: Array<[string, QueryValue]>): string {
  const q = new URLSearchParams();
  for (const [key, value] of entries) {
    if (value !== undefined) q.set(key, String(value));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

async function getJson<T>(path: string, tenant: string): Promise<T> {
  const res = await fetch(path, { headers: { 'X-Tenant-Id': tenant } });
  if (!res.ok) {
    throw new ApiError(res.status, `request failed (${res.status})`);
  }
  return (await res.json()) as T;
}

export function getCloudResources(
  tenant: string,
  params: CloudResourceQuery = {}
): Promise<Envelope<CloudResource[]>> {
  const qs = buildQuery([
    ['offset', params.offset],
    ['limit', params.limit],
    ['kind', params.kind],
    ['public', params.public],
  ]);
  return getJson(`/v1/inventory/cloud-resources${qs}`, tenant);
}

export function getVulnerabilities(
  tenant: string,
  params: VulnQuery = {}
): Promise<Envelope<VulnFinding[]>> {
  const qs = buildQuery([
    ['offset', params.offset],
    ['limit', params.limit],
    ['severity', params.severity],
    ['kev', params.kev],
  ]);
  return getJson(`/v1/findings/vulnerabilities${qs}`, tenant);
}

export function getVulnerability(tenant: string, cveId: string): Promise<Envelope<VulnDetail>> {
  return getJson(`/v1/findings/vulnerabilities/${encodeURIComponent(cveId)}`, tenant);
}

export function getCatalog(
  tenant: string,
  params: VulnQuery = {}
): Promise<Envelope<CatalogEntry[]>> {
  const qs = buildQuery([
    ['offset', params.offset],
    ['limit', params.limit],
    ['severity', params.severity],
    ['kev', params.kev],
  ]);
  return getJson(`/v1/findings/catalog${qs}`, tenant);
}

export function getPosture(tenant: string, domain?: string): Promise<Envelope<PostureSummary>> {
  const qs = domain ? `?domain=${encodeURIComponent(domain)}` : '';
  return getJson(`/v1/posture${qs}`, tenant);
}

export function getSbom(tenant: string): Promise<Envelope<SbomPackage[]>> {
  return getJson('/v1/inventory/sbom', tenant);
}

export function getContainerImages(tenant: string): Promise<Envelope<ContainerImage[]>> {
  return getJson('/v1/inventory/container-images', tenant);
}

export function getAvailableFixes(tenant: string): Promise<Envelope<AvailableFix[]>> {
  return getJson('/v1/findings/available-fixes', tenant);
}
