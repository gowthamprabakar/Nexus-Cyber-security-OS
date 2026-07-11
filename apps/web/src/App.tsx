import { useState } from 'react';
import { TenantProvider } from './auth/TenantProvider';
import { AvailableFixesPage } from './pages/AvailableFixesPage';
import { CloudResourcesPage } from './pages/CloudResourcesPage';
import { ContainerImagesPage } from './pages/ContainerImagesPage';
import { OverviewPage } from './pages/OverviewPage';
import { SbomPage } from './pages/SbomPage';
import { VulnCatalogPage } from './pages/VulnCatalogPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import './styles.css';

type View =
  | 'overview'
  | 'cloud-resources'
  | 'vulnerabilities'
  | 'sbom'
  | 'container-images'
  | 'vuln-catalog'
  | 'available-fixes';

const NAV: { view: View; label: string }[] = [
  { view: 'overview', label: 'Overview' },
  { view: 'cloud-resources', label: 'Cloud Resources' },
  { view: 'vulnerabilities', label: 'Vulnerabilities' },
  { view: 'sbom', label: 'SBOM' },
  { view: 'container-images', label: 'Container Images' },
  { view: 'vuln-catalog', label: 'Catalog' },
  { view: 'available-fixes', label: 'Available Fixes' },
];

export function App() {
  const [view, setView] = useState<View>('overview');
  return (
    <TenantProvider>
      <div className="app">
        <header className="app__bar">
          <span className="app__mark" aria-hidden="true" />
          <span className="app__title">Nexus Console</span>
          <nav className="app__nav">
            {NAV.map((n) => (
              <button
                key={n.view}
                type="button"
                className={view === n.view ? 'active' : ''}
                onClick={() => setView(n.view)}
              >
                {n.label}
              </button>
            ))}
          </nav>
        </header>
        <main className="app__main">
          {view === 'overview' && <OverviewPage />}
          {view === 'cloud-resources' && <CloudResourcesPage />}
          {view === 'vulnerabilities' && <VulnerabilitiesPage />}
          {view === 'sbom' && <SbomPage />}
          {view === 'container-images' && <ContainerImagesPage />}
          {view === 'vuln-catalog' && <VulnCatalogPage />}
          {view === 'available-fixes' && <AvailableFixesPage />}
        </main>
      </div>
    </TenantProvider>
  );
}
