import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { RowCount } from './RowCount';

describe('RowCount', () => {
  it('renders the true total, not the shown count', () => {
    render(<RowCount shown={50} total={130} noun="packages" />);
    expect(screen.getByText(/130 packages/)).toBeInTheDocument();
  });

  it('flags truncation when fewer rows are shown than the total', () => {
    render(<RowCount shown={50} total={130} noun="packages" />);
    expect(screen.getByText(/showing first 50/)).toBeInTheDocument();
  });

  it('shows no truncation note when everything is shown', () => {
    render(<RowCount shown={12} total={12} noun="images" />);
    expect(screen.getByText(/12 images/)).toBeInTheDocument();
    expect(screen.queryByText(/showing first/)).not.toBeInTheDocument();
  });

  it('falls back to the shown count when total is unknown', () => {
    render(<RowCount shown={7} total={null} noun="findings" />);
    expect(screen.getByText(/7 findings/)).toBeInTheDocument();
    expect(screen.queryByText(/showing first/)).not.toBeInTheDocument();
  });
});
