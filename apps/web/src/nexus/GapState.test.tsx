// apps/web/src/nexus/GapState.test.tsx
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { GapState } from './GapState';
describe('GapState', () => {
  it('names what the feature needs, no fake data', () => {
    render(<GapState title="End of Life" needs="an End-of-Life producer" />);
    expect(screen.getByText('End of Life')).toBeInTheDocument();
    expect(screen.getByText(/needs an End-of-Life producer/i)).toBeInTheDocument();
  });
});
