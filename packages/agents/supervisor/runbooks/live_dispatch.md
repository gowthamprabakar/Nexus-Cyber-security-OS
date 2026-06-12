# Runbook — Live Multi-Agent Dispatch (supervisor v0.2)

## What dispatches where

- The 11 closed-cycle v0.2 agents get **full** dispatch; remaining built agents get **basic**
  dispatch (`routing/live_registry.py`, Q1). A rule targeting an unknown agent is rejected.
- compliance depends on the posture agents — `order_by_dependencies` runs them first.

## Invariants on every delegation

- **WI-O8** `hierarchy.assert_no_peer_to_peer` — only `supervisor` may dispatch.
- **WI-O9** `contract_signing.assert_signed_contract` — every contract is HMAC-signed +
  verified; tampering (budget widening / re-targeting) invalidates the signature.
- **WI-O10** the event listener never subscribes to `claims.>`.
- **WI-O11** supervisor stays dispatcher-class: no Charter wrap, no tools, no OCSF emission.
