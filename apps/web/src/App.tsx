import { TenantProvider } from './auth/TenantProvider';
import { CloudResourcesPage } from './pages/CloudResourcesPage';
import './styles.css';

export function App() {
  return (
    <TenantProvider>
      <div className="app">
        <header className="app__bar">
          <span className="app__mark" aria-hidden="true" />
          <span className="app__title">Nexus Console</span>
        </header>
        <main className="app__main">
          <CloudResourcesPage />
        </main>
      </div>
    </TenantProvider>
  );
}
