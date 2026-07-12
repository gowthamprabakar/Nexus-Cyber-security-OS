// apps/web/src/nexus/useFetch.ts
import { useCallback, useEffect, useState } from 'react';

export type FetchState<T> =
  | { status: 'loading' }
  | { status: 'error'; message: string; retry: () => void }
  | { status: 'ready'; data: T };

export function useFetch<T>(fn: (tenant: string) => Promise<T>, tenant: string): FetchState<T> {
  const [state, setState] = useState<FetchState<T>>({ status: 'loading' });
  const run = useCallback(() => {
    let live = true;
    setState({ status: 'loading' });
    fn(tenant).then(
      (data) => {
        if (live) setState({ status: 'ready', data });
      },
      (e: unknown) => {
        if (live)
          setState({
            status: 'error',
            message: e instanceof Error ? e.message : 'Unknown error',
            retry: run,
          });
      }
    );
    return () => {
      live = false;
    };
  }, [fn, tenant]);
  useEffect(() => run(), [run]);
  return state;
}
