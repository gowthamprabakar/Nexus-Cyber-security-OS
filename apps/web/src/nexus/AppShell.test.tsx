import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { AppShell } from './AppShell';

// stub every page so the shell test is isolated to nav/routing
vi.mock('./ListPage', () => ({ ListPage: ({ view }: { view: string }) => <div>list:{view}</div> }));
vi.mock('./AuditChain', () => ({ AuditChain: () => <div>audit-page</div> }));
vi.mock('./GapState', () => ({
  GapState: ({ needs }: { needs: string }) => <div>gap:{needs}</div>,
}));

describe('AppShell', () => {
  it('renders the vuln sidebar and defaults to the Findings page', () => {
    render(<AppShell />);
    expect(screen.getByText('Vulnerability Findings')).toBeInTheDocument();
    expect(screen.getByText('list:vulnerabilities')).toBeInTheDocument();
  });
  it('navigates when a nav item is clicked', () => {
    render(<AppShell />);
    fireEvent.click(screen.getByText('SBOM'));
    expect(screen.getByText('list:sbom')).toBeInTheDocument();
  });
  it('routes bespoke + gap views', () => {
    render(<AppShell />);
    fireEvent.click(screen.getByText('Audit Chain'));
    expect(screen.getByText('audit-page')).toBeInTheDocument();
    fireEvent.click(screen.getByText('End of Life'));
    expect(screen.getByText(/gap:/)).toBeInTheDocument();
  });
});
