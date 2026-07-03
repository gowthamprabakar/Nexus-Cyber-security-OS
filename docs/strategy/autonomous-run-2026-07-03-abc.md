# Autonomous Run — 2026-07-03 — A + B + C (multi-cloud + correlation moat)

**Context:** operator out ~few days; directive "option a + b + c, each in high-level depth." This is the single source of truth for what was done and why. No operator check-ins possible → defensible defaults, documented.

## Operating mode

- Subagent-driven (implementer + per-task review + whole-branch adversarial review), ponytail + devil-critic throughout, husky-clean (no `--no-verify`).
- **Branches + PRs, NO merges** (operator merges on return). No other outward actions unrequested.
- Honest docs; "verified cross-cloud" = a CI test fires the detector on that cloud's fixture, nothing more.

## The three tracks

### A — Mixed-cloud ranking verification (cheap, real) — branch `feat/multi-cloud-attack-paths`

Verify the v0.5 expected-loss ranking produces a coherent top-N on a mixed AWS+Azure+GCP graph (v0.5 tests were AWS-only). Uses the ~10 already-wired cross-cloud archetypes. **Status: IN PROGRESS.**

### C — Toxic-combination correlation moat (net-new, highest value) — branch TBD

The Wiz differentiation: cross-agent toxic combinations. Scope + build core. **Status: PENDING (after A).**

### B — Azure/GCP KMS/SQL/VM multi-cloud (build, carefully) — branch `feat/multi-cloud-attack-paths`

**Cascade finding (why this is a build, not a verify):** multi-cloud-posture's CIS rule engine (`AZURE_CIS_RULES`/`GCP_CIS_RULES`) is DEAD CODE in the live pipeline (imported only in tests; production uses offline Defender/SCC feeds). Azure Key Vault, Azure VM, GCP Cloud KMS have NO public-exposure rule at all. No Azure/GCP spine writers (like cloud-posture's `record_kms_keys`/`record_rds_instances`/`record_ec2_workloads`); no canonical key builders for Azure Key Vault / GCP KMS. **Least-invasive plan:** build the spine writers + canonical keys + the missing detection logic + CI-REAL injectable-client tests (proves detection cross-cloud); do NOT unilaterally revive the deliberately-dead engine — document the production-emission wiring decision for the operator. **Status: PENDING (after C).**

## Decision log

(appended as decisions are made)

- 2026-07-03: sequence A→C→B (value + risk); B's engine-revival is an operator architecture decision, not an autonomous one.
