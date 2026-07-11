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

export interface SbomPackage {
  id: string;
  name: string;
  image: string;
  vulnerabilities: number;
}

export interface ContainerImage {
  id: string;
  packages: number;
  vulnerabilities: number;
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

export interface CatalogEntry {
  cve_id: string;
  severity: string;
  kev: boolean;
  epss: number | null;
  affected_resources: number;
}

export interface AvailableFix {
  component: string;
  fix_version: string;
  cve_count: number;
  resource_count: number;
  max_severity: string;
}

export interface AuditEvent {
  emitted_at: string;
  agent_id: string;
  action: string;
  correlation_id: string;
  source: string;
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

export interface Coverage {
  domains_covered: number;
  domains_total: number;
  domain_pct: number;
  collectors_ok: number | null;
  collectors_run: number | null;
  collector_pct: number | null;
  surfaced_findings: number;
  total_findings: number;
  surfaced_pct: number;
}

export interface DomainCount {
  domain: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ExposureFunnel {
  exposed: number;
  vulnerable: number;
  kev: number;
  exploitable: number;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface PostureSummary {
  tenant: string;
  scan_at: string;
  coverage: Coverage;
  totals: Record<string, number>;
  severity_distribution: SeverityDistribution;
  by_domain: DomainCount[];
  exposure_funnel: ExposureFunnel;
  inventory_counts: Record<string, number>;
}
