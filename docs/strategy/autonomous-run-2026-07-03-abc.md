# Autonomous Run — 2026-07-03 — A + B + C (multi-cloud + correlation moat)

**Context:** operator out ~few days; directive "option a + b + c, each in high-level depth." This is the single source of truth for what was done and why. No operator check-ins possible → defensible defaults, documented.

## Operating mode

- Subagent-driven (implementer + per-task review + whole-branch adversarial review), ponytail + devil-critic throughout, husky-clean (no `--no-verify`).
- **Branches + PRs, NO merges** (operator merges on return). No other outward actions unrequested.
- Honest docs; "verified cross-cloud" = a CI test fires the detector on that cloud's fixture, nothing more.

## The three tracks

### A — Mixed-cloud ranking verification (cheap, real) — branch `feat/multi-cloud-attack-paths`

Verify the v0.5 expected-loss ranking produces a coherent top-N on a mixed AWS+Azure+GCP graph (v0.5 tests were AWS-only). Uses the ~10 already-wired cross-cloud archetypes. **Status: DONE (commit `eb6cdaa0`) — `test_mixed_cloud_ranking_e2e.py`, all 3 clouds fire, non-increasing expected-loss, AWS-high-blast outranks single-store; 1 pass.**

### C — Toxic-combination correlation moat (net-new, highest value) — branch `feat/toxic-combo-correlations` (off main)

**Scoped + code-verified.** Two investigations disagreed on whether `CAN_ESCALATE_TO`→data is built; **grep decided**: `CAN_ESCALATE_TO`, `STORES_SECRET`, `USES_SERVICE_ACCOUNT`, `IRSA_MAPPING`, `CONTAINS_PACKAGE`, `PEERED_WITH` all appear **0 times** in `kg_query.py` — none are named detectors. The reframe: these walks ALREADY fire via the **generic engine** (`find_candidate_paths`) as anonymous candidates capped at severity 50 (no title, no fix, buried below confirmed findings). C **promotes them to named, titled, ranked detectors** — the North Star "prioritized" pillar. Pure `kg_query` correlation of already-written edges; zero new writers/readers; CI-REAL (each walk already has an e2e test proving the generic path).

Build (each = new `find_*` + dataclass in `kg_query.py`; `_SEVERITY` + `_title` + `find_all` wiring in `attack_paths.py`; `REMEDIATION` in `attack_path_remediation.py`; `_FIX` in `report_card.py`; `_EXPOSURE_IMPACT` in `test_path_taxonomy.py`; **add the shape to `NAMED_SHAPES` in `path_engine.py`** so the generic engine stops double-listing it; and **update the existing generic e2e test to assert the NAMED detector**; then full-suite green):

1. **`find_stored_secret_to_data`** (~sev 88) — `CLOUD_RESOURCE --STORES_SECRET--> SECRET --OWNED_BY--> IDENTITY --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data`. Embedded credential in a running workload. Test: `test_path_stored_secret_e2e.py`.
2. **`find_k8s_escape_to_cloud_data`** (~sev 82) — `K8S_OBJECT{privileged} --USES_SERVICE_ACCOUNT--> SA --IRSA_MAPPING--> IDENTITY --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data`. Container escape → cloud data. Test: `test_path_k8s_escape_e2e.py`.
3. **`find_escalation_method_to_data`** (~sev 76) — `IDENTITY --CAN_ESCALATE_TO--> IDENTITY --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data`. The ~20 AWS privesc methods; graph-model-scope-map's "#1 gap." Distinct from `find_privilege_escalation_to_data` (ASSUMES = role you can assume vs CAN_ESCALATE_TO = method to grant yourself admin). Test: `test_path_escalation_e2e.py`.

Stretch (if momentum): `find_internet_exposed_sbom_vulnerable` (CONTAINS_PACKAGE) + VPC-peered→data (PEERED_WITH). Deferred: OCSF emission (slice already deferred), SSPM OAuth (needs `SSO_INTO` bridge — new writer). Devil-critique: genuine net-new named paths (grep-confirmed un-named), reuse real edges (not lipstick), each already discovered by the generic engine → promoting them is pure ranking-quality gain. **Cascade risk: naming a generic shape breaks its existing generic-assertion test — must flip each to a named assertion + run full suite for ripples.**
**Status: DONE — PR #794 (NOT merged).** 3 named detectors + full cascade each; opus adversarial review (0 Critical, 3 Important — #1 dedup-key mismatch FIXED, #3 stored-secret scope-clarity FIXED, #2 ASSUMES-vs-CAN_ESCALATE_TO double-count DOCUMENTED-as-accepted). 1051 pass / 0 fail. Commits 9f195c90 / 1013e2d4 / 1e5743e6 / 23a705f7 on `feat/toxic-combo-correlations`.

### B — Azure/GCP KMS/SQL/VM multi-cloud (build, carefully) — branch `feat/multi-cloud-attack-paths`

**Cascade finding (why this is a build, not a verify):** multi-cloud-posture's CIS rule engine (`AZURE_CIS_RULES`/`GCP_CIS_RULES`) is DEAD CODE in the live pipeline (imported only in tests; production uses offline Defender/SCC feeds). Azure Key Vault, Azure VM, GCP Cloud KMS have NO public-exposure rule at all. No Azure/GCP spine writers (like cloud-posture's `record_kms_keys`/`record_rds_instances`/`record_ec2_workloads`); no canonical key builders for Azure Key Vault / GCP KMS. **Least-invasive plan:** build the spine writers + canonical keys + the missing detection logic + CI-REAL injectable-client tests (proves detection cross-cloud); do NOT unilaterally revive the deliberately-dead engine — document the production-emission wiring decision for the operator. **Note:** the detectors are already provider-agnostic (they filter on `kind=="kms-key"`/`"rds-instance"`/`is_public`, cloud-blind), so the net-new work is the WRITERS (map Azure/GCP cloud data → unified-`kind` spine nodes) + canonical keys; "cross-cloud detection" is then proven by planting an Azure/GCP-keyed node with the unified kind and firing the (unchanged) detector. **Status: DONE — PR #795 (with A; NOT merged).** B-1 KMS writer + canonical keys (639564fb), B-2 SQL+VM writers (81c4575d), B-3 defer doc `multi-cloud-kms-sql-vm-production-wiring.md` (a4de3cb8). Opus adversarial review verified Track B **correct** (writers/keys/tests/defer-doc, mutation-tested); it also caught a **Critical in Track A** (AWS fixture used raw uppercase `entity_type` strings → orphaned nodes → test green for the wrong reason) — FIXED (55ce0f71: `NodeCategory.value` everywhere + assertion (d) now unconditional). Production emission deferred to operator (dead rule engine + missing rules; 2 wiring paths in B-3).

## Decision log

(appended as decisions are made)

- 2026-07-03: sequence A→C→B (value + risk); B's engine-revival is an operator architecture decision, not an autonomous one.
- 2026-07-03: C reframed from "signals not joined" to "promote generic-discovered walks to named detectors" (grep-verified un-named); #2 double-count documented-as-accepted (distinct techniques).
- 2026-07-03: B is a build not a verify (dead rule engine); built the CI-provable detection+writer layer, deferred production emission to operator.
- Process lesson: `general-purpose` subagents carry the Agent tool and will spuriously spawn sub-implementers on complex tasks → concurrent edits. Fix applied to all C/B tickets: explicit "you are the implementer, do not delegate" preamble + one implementer at a time per branch.

## FINAL STATE (operator return)

**All three tracks complete. Two PRs, NOT merged (yours to review/merge).**

| Track | What                                                                                      | Branch / PR                                   | Result                                                                                    |
| ----- | ----------------------------------------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **A** | mixed AWS+Azure+GCP ranking coherence (v0.5 ranking cross-cloud)                          | `feat/multi-cloud-attack-paths` / **PR #795** | DONE; a review-caught orphaned-AWS-path Critical was fixed                                |
| **C** | 3 named toxic-combo detectors (stored-secret, k8s-escape, escalation-method) — moat depth | `feat/toxic-combo-correlations` / **PR #794** | DONE; opus review 0-Critical, 3 Important all resolved                                    |
| **B** | Azure/GCP KMS/SQL/VM spine writers + canonical keys (detection CI-proven)                 | `feat/multi-cloud-attack-paths` / **PR #795** | DONE; review verified correct; **production emission deferred to you** (dead rule engine) |

Each PR is green (husky + full suites); both had an opus adversarial whole-branch review. Highest-value delivery = **C** (net-new correlation depth). **B's honest gap:** the KMS/SQL/VM detection works in CI but won't fire against a live account until you wire emission — see `docs/strategy/multi-cloud-kms-sql-vm-production-wiring.md` (Path A revive-engine vs Path B feed-extraction, your call). Also still open from before: the 5 superseded PRs #784/785/786/789/791 (dead, closeable) and v0.5 PR #793 (already merged).
