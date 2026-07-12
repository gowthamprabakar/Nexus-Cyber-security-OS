// apps/web/src/nexus/listConfig.ts (Findings entry; extended in later tasks)
import {
  getCatalog,
  getAvailableFixes,
  getCloudResources,
  getContainerImages,
  getSbom,
  getVulnerabilities,
} from '../api/client';
import type { View } from './nav';

export type Column = {
  label: string;
  key: string;
  type: 'text' | 'mono' | 'two' | 'sev' | 'status' | 'epss' | 'kev';
  // Flex ratio approximating the mock's per-column proportions (default 1).
  fb?: number;
};
export type ListConfig = {
  title: string;
  attribution: string;
  fetch: (tenant: string) => Promise<Record<string, unknown>[]>;
  columns: Column[];
  // §9 #6: findings default to EPSS-descending so the exploitable backlog is triage-first.
  defaultSort?: 'epss-desc';
};

const titleCase = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : '');

export const LIST_CONFIG: Partial<Record<View, ListConfig>> = {
  vulnerabilities: {
    title: 'Vulnerability Findings',
    attribution: 'Discovered by D.1 Vulnerability v0.1 · + D.7 Threat Intel',
    defaultSort: 'epss-desc',
    fetch: async (t) =>
      (await getVulnerabilities(t, { limit: 500 })).data.map((r) => ({
        cve: r.cve_id,
        resource: r.resource,
        component: r.component || '—',
        status: 'Unresolved',
        severity: titleCase(r.severity),
        fix: r.fix_version || '—',
        kev: r.kev,
        epss: r.epss,
        _raw: r,
      })),
    columns: [
      { label: 'Finding', key: 'cve', type: 'mono', fb: 1.6 },
      { label: 'Resource', key: 'resource', type: 'two', fb: 1.5 },
      { label: 'Component', key: 'component', type: 'two', fb: 1.5 },
      { label: 'Status', key: 'status', type: 'status', fb: 1 },
      { label: 'Severity', key: 'severity', type: 'sev', fb: 1 },
      // §9 #1: EPSS + KEV are the persona's triage signals — real fields from D.7 enrichment.
      { label: 'EPSS', key: 'epss', type: 'epss', fb: 0.7 },
      { label: 'KEV', key: 'kev', type: 'kev', fb: 0.7 },
      { label: 'Fix', key: 'fix', type: 'mono', fb: 0.9 },
    ],
  },

  'vuln-catalog': {
    title: 'Vulnerability Catalog',
    attribution: 'Discovered by D.1 Vulnerability v0.1',
    fetch: async (t) =>
      (await getCatalog(t, { limit: 500 })).data.map((r) => ({
        cve: r.cve_id,
        severity: titleCase(r.severity),
        kev: r.kev ? 'KEV' : '—',
        epss: r.epss ?? '—',
        affected: r.affected_resources,
      })),
    columns: [
      { label: 'CVE', key: 'cve', type: 'mono', fb: 1.6 },
      { label: 'Severity', key: 'severity', type: 'sev', fb: 1 },
      { label: 'KEV', key: 'kev', type: 'text', fb: 0.7 },
      { label: 'EPSS', key: 'epss', type: 'mono', fb: 0.8 },
      { label: 'Affected', key: 'affected', type: 'mono', fb: 0.9 },
    ],
  },

  patch: {
    title: 'Patch Management',
    attribution: 'Discovered by D.1 Vulnerability v0.1',
    fetch: async (t) =>
      (await getAvailableFixes(t)).data.map((r) => ({
        component: r.component,
        fix_version: r.fix_version,
        cve_count: r.cve_count,
        resource_count: r.resource_count,
        severity: titleCase(r.max_severity),
      })),
    columns: [
      { label: 'Package', key: 'component', type: 'two', fb: 1.5 },
      { label: 'Fix version', key: 'fix_version', type: 'mono', fb: 1.2 },
      { label: 'CVEs', key: 'cve_count', type: 'mono', fb: 0.7 },
      { label: 'Resources', key: 'resource_count', type: 'mono', fb: 0.9 },
      { label: 'Severity', key: 'severity', type: 'sev', fb: 1 },
    ],
  },

  sbom: {
    title: 'SBOM',
    attribution: 'Discovered by D.1 Vulnerability v0.1',
    fetch: async (t) =>
      (await getSbom(t)).data.map((r) => ({
        package: r.name,
        image: r.image,
        vulnerabilities: r.vulnerabilities,
      })),
    columns: [
      { label: 'Package', key: 'package', type: 'two', fb: 1.5 },
      { label: 'Image', key: 'image', type: 'mono', fb: 1.5 },
      { label: 'Vulnerabilities', key: 'vulnerabilities', type: 'mono', fb: 1 },
    ],
  },

  'container-images': {
    title: 'Container Images',
    attribution: 'Discovered by D.1 Vulnerability v0.1',
    fetch: async (t) =>
      (await getContainerImages(t)).data.map((r) => ({
        image: r.id,
        packages: r.packages,
        vulnerabilities: r.vulnerabilities,
      })),
    columns: [
      { label: 'Image', key: 'image', type: 'mono', fb: 2 },
      { label: 'Packages', key: 'packages', type: 'mono', fb: 0.9 },
      { label: 'Vulnerabilities', key: 'vulnerabilities', type: 'mono', fb: 1 },
    ],
  },

  'cloud-resources': {
    title: 'Cloud Resources',
    attribution: 'Discovered by F.3/D.5 Cloud Posture',
    fetch: async (t) =>
      (await getCloudResources(t, { limit: 500 })).data.map((r) => ({
        resource: r.id,
        kind: r.kind,
        cloud: r.cloud,
        public: r.is_public ? 'Public' : 'Private',
        region: r.region ?? '—',
      })),
    columns: [
      { label: 'Resource', key: 'resource', type: 'two', fb: 2 },
      { label: 'Kind', key: 'kind', type: 'text', fb: 1 },
      { label: 'Cloud', key: 'cloud', type: 'text', fb: 0.7 },
      { label: 'Public', key: 'public', type: 'status', fb: 0.8 },
      { label: 'Region', key: 'region', type: 'mono', fb: 1 },
    ],
  },
};
