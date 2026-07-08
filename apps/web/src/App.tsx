import { useState } from 'react';
import { TenantProvider } from './auth/TenantProvider';
import { CloudResourcesPage } from './pages/CloudResourcesPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import './styles.css';

type View = 'cloud-resources' | 'vulnerabilities';

export function App() {
  const [view, setView] = useState<View>('cloud-resources');
  return (
    <TenantProvider>
      <div className="app">
        <header className="app__bar">
          <span className="app__mark" aria-hidden="true" />
          <span className="app__title">Nexus Console</span>
          <nav className="app__nav">
            <button
              type="button"
              className={view === 'cloud-resources' ? 'active' : ''}
              onClick={() => setView('cloud-resources')}
            >
              Cloud Resources
            </button>
            <button
              type="button"
              className={view === 'vulnerabilities' ? 'active' : ''}
              onClick={() => setView('vulnerabilities')}
            >
              Vulnerabilities
            </button>
          </nav>
        </header>
        <main className="app__main">
          {view === 'cloud-resources' ? <CloudResourcesPage /> : <VulnerabilitiesPage />}
        </main>
      </div>
    </TenantProvider>
  );
}
