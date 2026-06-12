# Changelog — nexus-remediation-agent (A.1)

## v0.2.0 (Cycle 16 of 17 — ⚠️ SAFETY-CRITICAL CYCLE — EXTRA DISCIPLINE)

A.1 is the **only agent that mutates customer infrastructure**, so this cycle carries extra
safety discipline: all 6 decision heuristics (H1–H6) are formalized at code level as institutional
invariants, plus 2 new action-specific invariants and the tool-proxy + tenant guards.

- **7 action classes** (5 existing + `K8S_PATCH_DISABLE_PRIVILEGED_CONTAINER` +
  `K8S_PATCH_DISABLE_AUTO_MOUNT_SA_TOKEN`; host-network/pid/ipc deferred to v0.3).
- **10 code-level safety invariants** under `remediation/invariants/` (H1–H6 + 2 action-specific +
  tool-proxy + tenant).
- K8s-relevant source consumption (k8s-posture + F.3 + D.5).
- Batched multi-finding mode (opt-in; batch cap ≤ H5's 50).
- Continuous-monitoring infrastructure (production loop = Phase C, not v0.3).
- OCSF 2007 preserved — A.1 remains the sole 2007 producer.

The **final v0.2 infrastructure cycle**; the Phase C production-loop wiring sprint launches next.

## v0.1.x

Initial release — 5 K8s patch action classes, 3 operational tiers (recommend/dry-run/execute),
7-stage promotion pipeline, dual audit chain, OCSF 2007 emission.
