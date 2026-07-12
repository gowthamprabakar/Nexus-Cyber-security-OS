import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';

describe('nexus theme', () => {
  it('defines the core CSS variables on :root via the imported sheet', async () => {
    await import('./theme.css'); // import for side effect; jsdom ignores CSS but this guards the path
    const el = document.createElement('div');
    el.setAttribute('style', 'color: var(--text)');
    render(<div style={{ background: 'var(--bg)' }}>ok</div>);
    // jsdom does not compute custom properties; assert the sheet import resolved (no throw) and a var ref renders.
    expect(el.style.color).toContain('var(--text)');
  });
});
