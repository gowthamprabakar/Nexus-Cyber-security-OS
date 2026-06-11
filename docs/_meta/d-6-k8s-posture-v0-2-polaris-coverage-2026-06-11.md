# k8s-posture v0.2 — Polaris Coverage (WI-K1)

**Date:** 2026-06-11 · Measured **per-tool**, no aggregate (WI-K1).

## Covered at v0.2

- Live Polaris policy-check execution against a **running cluster** (kubeconfig-based,
  injectable runner) via `tools/polaris_live.py`, alongside the offline `read_polaris`.
- Byte-identical parse with the offline reader (shared `_extract_results` + `_walk_workload`;
  `model_dump` equality test) → OCSF 2003 via the shared normalizer.
- **Custom policy support** (`polaris/custom_policy.py`): per-check enable/disable + severity
  overrides loaded from the customer profile (`customer_context.md` frontmatter), defaults
  preserved when none declared.

## NOT covered (v0.3+)

- Running `polaris audit` against the live API server end-to-end (prod runner defined; CI
  uses an injected fake — WI-K3 honest scope).
- The full Polaris check catalog beyond the workload/pod/container checks the offline reader
  parses.
- Polaris exemptions / mutating-webhook config (read-only audit only).

## Honest estimate

**~50-60% `[estimate]`** of the Polaris signal a workload-policy consumer wants — solid on
live execution + byte-identical normalization + custom-policy overlay, absent on the full
check catalog + the live-audit execution loop. Estimate, not a measured benchmark.
