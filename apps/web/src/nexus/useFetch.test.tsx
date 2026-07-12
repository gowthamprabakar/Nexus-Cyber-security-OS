// apps/web/src/nexus/useFetch.test.tsx
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { useFetch } from './useFetch';

function Probe({ fn }: { fn: (t: string) => Promise<string> }) {
  const s = useFetch(fn, 'dev');
  if (s.status === 'loading') return <div>loading</div>;
  if (s.status === 'error') return <button onClick={s.retry}>err:{s.message}</button>;
  return <div>data:{s.data}</div>;
}

describe('useFetch', () => {
  it('resolves to ready with data', async () => {
    render(<Probe fn={() => Promise.resolve('hi')} />);
    expect(await screen.findByText('data:hi')).toBeInTheDocument();
  });
  it('captures errors and retries', async () => {
    const fn = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce('ok');
    render(<Probe fn={fn} />);
    fireEvent.click(await screen.findByText('err:boom'));
    expect(await screen.findByText('data:ok')).toBeInTheDocument();
  });
});
