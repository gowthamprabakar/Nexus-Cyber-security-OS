// apps/web/src/nexus/listConfig.ts (Findings entry; extended in later tasks)
import { getVulnerabilities } from '../api/client';
import type { View } from './nav';

export type Column = {
  label: string;
  key: string;
  type: 'text' | 'mono' | 'two' | 'sev' | 'status';
  // Flex ratio approximating the mock's per-column proportions (default 1).
  fb?: number;
};
export type ListConfig = {
  title: string;
  attribution: string;
  fetch: (tenant: string) => Promise<Record<string, unknown>[]>;
  columns: Column[];
};

const titleCase = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : '');

export const LIST_CONFIG: Partial<Record<View, ListConfig>> = {
  vulnerabilities: {
    title: 'Vulnerability Findings',
    attribution: 'Discovered by D.1 Vulnerability v0.1 · + D.7 Threat Intel',
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
      { label: 'Fix', key: 'fix', type: 'mono', fb: 0.9 },
    ],
  },
};
