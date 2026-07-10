import { useState } from 'react';
import { TenantProvider } from './auth/TenantProvider';
import { CloudResourcesPage } from './pages/CloudResourcesPage';
import { OverviewPage } from './pages/OverviewPage';
import { SbomPage } from './pages/SbomPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import './styles.css';

type View = 'overview' | 'cloud-resources' | 'vulnerabilities' | 'sbom';

const NAV: { view: View; label: string }[] = [
  { view: 'overview', label: 'Overview' },
  { view: 'cloud-resources', label: 'Cloud Resources' },
  { view: 'vulnerabilities', label: 'Vulnerabilities' },
  { view: 'sbom', label: 'SBOM' },
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
        </main>
      </div>
    </TenantProvider>
  );
}
