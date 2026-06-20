# Fleet Test Level 1 (Integration / wiring smoke) — CLOSED

_2026-06-20 · v0.4 Fleet Test Directive v2 (#766) §2 · meta-brainstorm #767 · L1 brainstorm #768_

## Scope delivered

| PR       | What                                                                                             | Review                                  |
| -------- | ------------------------------------------------------------------------------------------------ | --------------------------------------- |
| **#769** | `packages/integration` + `fleet_testkit` + 2 reference harnesses (cloud-posture, runtime-threat) | per-PR review (infra)                   |
| **#770** | the other 18 agent wiring harnesses + `fleet_testkit` bare-OCSF/str support                      | per-PR review (infra change + findings) |

All **20 agents** now have `packages/agents/<agent>/tests/integration/test_wiring.py`.

## Level 1 PASS (§2.5)

- **All 20 wiring harnesses green** — 35 tests (most agents 2: full + inert-offline; Tier-B
  orchestration agents 1).
- **0 integration false-negatives** — every Tier-A agent's seeded run produces its findings;
  every kg-writing agent writes its expected node type.
- **F.6 audit chain hash-verifies** — `assert_audit_chain` recomputes each `entry_hash` via the
  real `charter.audit._hash_entry` (not just link-checking) across every agent that writes one.
- **Tenant isolation across all 20** — `assert_two_tenant_disjoint` (graph writers) /
  per-finding tenant tags (bare-OCSF agents) run in every harness; inert-offline proves no writes
  without a store.

`fleet_testkit` L1 surface: `in_memory_semantic_store`, `assert_ocsf_valid` (bare-or-enveloped),
`assert_entity_written` / `assert_no_entities` / `assert_two_tenant_disjoint` (NodeCategory **or**
raw entity_type str), `assert_audit_chain`, `wiring_contract`.

## Tiers (no fake-greens — every omission documented in-test, swiss-bar #5/#12)

- **14 Tier A** (full §2.3): vulnerability, cloud-posture, multi-cloud-posture, k8s-posture,
  data-security, identity, threat-intel, sspm, aispm, runtime-threat, network-threat, appsec,
  curiosity, synthesis.
- **2 Tier B read-only**: compliance, investigation (drop kg-write, documented).
- **1 Tier B action**: remediation (OCSF 2007 action shape; A.1-specific dual-chain audit check).
- **3 Tier B orchestration**: audit (6003 via F.6), supervisor (routing, no OCSF/graph),
  meta-harness (scorecard entity, no findings.json OCSF).

## Findings (operator-ruled 2026-06-20)

1. **bare-OCSF fleet split** — 6 agents (appsec, curiosity, synthesis, investigation,
   remediation, audit) emit bare OCSF in their findings file; the rest wrap via `wrap_ocsf`.
   **Ruling:** §2.3 literal ("valid OCSF") → relaxed helper accepted for v0.4 L1; the universal
   `NexusEnvelope` invariant is an architectural ADR question, not a wiring bug. **appsec flagged
   as a v0.5 architectural anomaly** (a detection agent in the same class as the wrapped detection
   agents). → v0.5 backlog.
2. **raw entity_type debt** — threat-intel (`cve`/`ttp`), curiosity (`hypothesis`), synthesis
   (`synthesis_report`) persist non-`NodeCategory` strings. **Ruling:** honest write path beats
   invented enums; relaxed helper accepted. → v0.5 ADR-018 migration backlog.
3. **4 `__init__.py` removals** — investigation/remediation/curiosity/synthesis
   `tests/integration/__init__.py` forced `test_wiring.py` to a shared importlib module name and
   collided. **Ruling:** pytest hygiene fix, approved. Affected agents' full suites re-verified.

## Carried to v0.5 (`docs/_meta/backlog/v0-5.md`)

- **NexusEnvelope universal-invariant ADR** (appsec architectural anomaly first).
- **ADR-018 migration** for raw entity_types `cve` / `ttp` / `hypothesis` / `synthesis_report`.

L2 capability tests for the 6 bare-emit agents use the same bare-or-wrapped validation as L1.

## Next

L2 — per-agent capability test-case banks (~146 YAML cases; INPUT + GROUND TRUTH + PASS CRITERIA;
measured precision/recall/FP). **Per-PR review on EVERY L2 agent bank** (Q9 sharpening — ground
truth correctness is semantic, CI can't catch it). L3–L6 follow; Stage 4 Wazuh + Stage 5 close
after L6.
