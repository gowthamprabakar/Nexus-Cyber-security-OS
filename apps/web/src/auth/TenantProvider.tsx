import { createContext, useContext, useMemo, type ReactNode } from 'react';

// Auth/RBAC shell. STUBBED now (single dev tenant, allow-all) behind a real interface,
// so the real IdP + entitlement service can be swapped in later without changing callers.

interface TenantContextValue {
  tenant: string;
}

const TenantContext = createContext<TenantContextValue | null>(null);

export function TenantProvider({
  tenant = 'dev',
  children,
}: {
  tenant?: string;
  children: ReactNode;
}) {
  const value = useMemo<TenantContextValue>(() => ({ tenant }), [tenant]);
  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>;
}

export function useTenant(): string {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error('useTenant must be used within a TenantProvider');
  return ctx.tenant;
}
