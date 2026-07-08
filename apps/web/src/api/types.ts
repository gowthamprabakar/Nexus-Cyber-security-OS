// Mirrors the read-API contract (docs/strategy/2026-07-08-read-api-contract.md).

export interface Meta {
  offset: number | null;
  total: number | null;
  tenant: string;
  generated_at: string;
}

export interface Envelope<T> {
  data: T;
  meta: Meta;
}

export interface CloudResource {
  id: string;
  kind: string;
  cloud: string;
  is_public: boolean;
  region: string | null;
}

export interface VulnFinding {
  cve_id: string;
  severity: string;
  kev: boolean;
  epss: number | null;
  resource: string;
  component: string;
  fix_version: string;
  status: string;
}

export interface VulnRemediation {
  tier: string;
  advice: string;
}

export interface VulnDetail {
  cve_id: string;
  severity: string;
  kev: boolean;
  epss: number | null;
  cvss_v3_score: number | null;
  cwe: string[];
  description: string;
  component: string;
  fix_version: string;
  affected_resources: string[];
  first_seen: string | null;
  remediation: VulnRemediation;
}
