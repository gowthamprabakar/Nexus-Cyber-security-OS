export type View =
  | 'vulnerabilities'
  | 'vuln-catalog'
  | 'patch'
  | 'sbom'
  | 'container-images'
  | 'cloud-resources'
  | 'audit'
  | 'overview'
  | 'inventory-overview'
  | 'eol'
  | 'cure-recommend'
  | 'cure-dryrun'
  | 'cure-execute';

export interface NavItem {
  label: string;
  view: View;
  icon: string;
}

export interface NavSection {
  section: string;
  items: NavItem[];
}

export const VULN_NAV: NavSection[] = [
  {
    section: 'Boards',
    items: [
      { label: 'Vulnerability Overview', view: 'overview', icon: 'board' },
      { label: 'Patch Management', view: 'patch', icon: 'clip' },
    ],
  },
  {
    section: 'Findings',
    items: [
      { label: 'Vulnerability Findings', view: 'vulnerabilities', icon: 'bug' },
      { label: 'End of Life', view: 'eol', icon: 'clip' },
    ],
  },
  {
    section: 'Inventory',
    items: [
      { label: 'Inventory Overview', view: 'inventory-overview', icon: 'box' },
      { label: 'SBOM', view: 'sbom', icon: 'box' },
      { label: 'Container Images', view: 'container-images', icon: 'box' },
      { label: 'Cloud Resources', view: 'cloud-resources', icon: 'cube' },
    ],
  },
  {
    section: 'Cure',
    items: [
      { label: 'Recommend Queue', view: 'cure-recommend', icon: 'check' },
      { label: 'Dry-Run Queue', view: 'cure-dryrun', icon: 'play' },
      { label: 'Execute Queue', view: 'cure-execute', icon: 'bolt' },
      { label: 'Audit Chain', view: 'audit', icon: 'chain' },
    ],
  },
  {
    section: 'Policies',
    items: [{ label: 'Vulnerability Catalog', view: 'vuln-catalog', icon: 'doc' }],
  },
];
