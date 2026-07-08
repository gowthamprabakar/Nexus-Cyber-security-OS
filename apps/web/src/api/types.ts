// Mirrors the read-API contract (docs/strategy/2026-07-08-read-api-contract.md).

export interface Meta {
  offset: number | null;
  total: number | null;
  tenant: string;
  generated_at: string;
}

export interface Envelope<T> {
  data: T;
  meta: Meta;
}

export interface CloudResource {
  id: string;
  kind: string;
  cloud: string;
  is_public: boolean;
  region: string | null;
}
