# KG-Loop Closure — Verification Record (v0.1, 2026-05-18)

**Companion record for** [`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`](../superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md). Records the full execution of the KG-loop-closure plan against the user-stated requirements, the watch-items, the ADR-010 eligibility conditions, the keystone live proof, and the carry-forward debts. Plan-closer; same A.1 v0.1.1-grade discipline as [`a1-v0-1-1-verification-2026-05-17.md`](a1-v0-1-1-verification-2026-05-17.md) and [`a1-verification-2026-05-16.md`](a1-verification-2026-05-16.md). **Agent does not quick-merge this PR.**

---

## §1. What v0.1 of the KG-loop closure delivered

**Goal achieved.** The knowledge-graph read/write loop that the F.5 pivot severed across two stores is closed by execution against real Postgres. Cloud Posture writes asset + finding entities and AFFECTS edges to the platform's `SemanticStore`; D.7 Investigation's `memory_neighbors_walk` reads them back via the same store. The keystone is now load-bearing AND loaded.

**Eight tasks landed across PRs #33–#39** on the path from the orphaned `neo4j_kg.py` (F.3 Task 6, 2026-05-08) to a fully wired SemanticStore-backed `KnowledgeGraphWriter` with: an ADR amendment, an empirical single-agent grep audit, the new writer + agent rewire (SAFETY-CRITICAL), mocked unit tests with full dedup coverage, an additive-only eval back-compat gate, a live-postgres proof on CI (SAFETY-CRITICAL), a DORMANT-bannered preservation of the legacy Neo4j writer, and this verification record.

**No charter change. No other agent change. No deletion.** Watch-items 1, 2, 3 held end-to-end.

**Three follow-ups carried forward** as named, tracked debts: the within-vs-cross-run dedup boundary, a charter-substrate LTREE bug discovered in CI, and one plan-row-letter-vs-spirit deviation.

---

## §2. Per-task surface table (eight hash-pins)

| #   | Risk                | PR                                                                                    | Implementation commit                                                                  | Merge commit                            | What landed                                                                                                                                                                                                                                                                                                                                                                 |
| --- | ------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | LOW-RISK            | [#33](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/33)             | `d95916b`                                                                              | `3f5c5c9`                               | ADR-009 amendment: 76-line "Amendment 2026-05-18 — Cloud Posture rerouted to SemanticStore; Neo4j writer preserved dormant" section recording the four-event timeline, the absence-of-sweep observation, the verbatim reroute decision, the data-model mapping, the NEW `MemoryService.semantic`-only rule, and the reaffirmed Phase-2 escape-hatch trigger.                |
| 2   | LOW-RISK            | [#34](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/34)             | `ec165f2`                                                                              | `4b3c8f6`                               | Empirical grep audit (`docs/_meta/kg-loop-task-2-grep-audit-2026-05-18.md`, 161 lines): 6 search surfaces × `packages/` confirmed **0 matches** of any Neo4j-related symbol outside `packages/agents/cloud-posture/`; 15 inside, all accounted for.                                                                                                                         |
| 3   | **SAFETY-CRITICAL** | [#35](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/35)             | `8b883c2`                                                                              | `7bf835c`                               | `kg_writer.py` (NEW, 113 lines) + `agent.py` rewire (`neo4j_driver: Any \| None` → `semantic_store: SemanticStore \| None`, disclosed param rename); F.6 audit-chain action names preserved (`kg_upsert_asset`, `kg_upsert_finding`); per-finding AFFECTS-edge dedup table; module + callers + tests + README + runbook updated. Verified-against-HEAD sentence in PR body. |
| 4   | LOW-RISK            | [#36](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/36)             | `e146976`                                                                              | `9f49565`                               | `tests/test_kg_writer.py` (NEW, ~370 lines): **12 mocked unit tests** across 4 claim-shapes — payload shape (4), empty-arns no-op (1), AFFECTS plumbing + entity-id round-trip (2), AFFECTS-edge dedup (4 — canonical / within-call / cross-finding / mixed), tenant propagation (1).                                                                                       |
| 5   | LOW-RISK            | [#37](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/37)             | `acd340e`                                                                              | `10a06a1`                               | `tests/test_kg_loop_eval_back_compat.py` (NEW, ~198 lines): runs the full 10-case Cloud Posture eval suite TWICE per case (semantic_store=None vs in-memory aiosqlite SemanticStore) and asserts per-case dict-equality across 6 deterministic actuals dimensions. Test-boundary monkeypatch + contract-whitelist expansion; production code unchanged.                     |
| 6   | **SAFETY-CRITICAL** | [#38](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/38)             | `e9fc326` (initial), `bf7e37d` (path fix), `edae2b9` (LTREE workaround / drop alembic) | _(merge sha to be recorded post-merge)_ | `tests/integration/test_kg_loop_live_postgres.py` (NEW, ~463 lines): 3 tests gated by `NEXUS_LIVE_POSTGRES=1` — loop-closes-via-D.7-walker, REPEATED-WRITE-yields-one-AFFECTS-edge, semantic_store=None-leaves-substrate-untouched. Skip-discipline mirrors charter's F.5 live lane.                                                                                        |
| 6a  | LOW-RISK            | [#38](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/38) (folded in) | `e50e7c2` (workflow), iterations `bf7e37d` / `da336cd` (later reverted) / `edae2b9`    | _(merge sha to be recorded post-merge)_ | `.github/workflows/kg-loop-live.yml`: standalone CI lane with `pgvector/pgvector:pg16` service container, `POSTGRES_USER=nexus`, paths-filtered to KG surfaces. **CI run [26055249482](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482) is the keystone proof of record (3 passed in 2.46s).**                                          |
| 7   | LOW-RISK            | [#39](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/pull/39)             | `547452d`                                                                              | _(merge sha to be recorded post-merge)_ | DORMANT banner prepended to `tools/neo4j_kg.py` module docstring (plan-row-7 verbatim). Historical docstring preserved beneath. Zero deletion.                                                                                                                                                                                                                              |
| 8   | LOW-RISK            | _this PR_                                                                             | _this commit_                                                                          | _(merge sha to be recorded post-merge)_ | **This verification record.** Plan-closer; full A.1-grade review; three carry-forward debts named explicitly.                                                                                                                                                                                                                                                               |

Per-PR sha post-merge: row 6 / 6a / 7 / 8 merge-commit shas are recorded on a follow-up doc-only commit after each lands; the entries above intentionally leave `_to be recorded post-merge_` rather than fabricate values.

---

## §3. Local gates (final aggregate, this branch)

All gates run against this branch's HEAD before commit. Branch tip at write time: `feat/kg-loop-task-8-verification-record`.

| Gate                                                       | Result                                                                                                                                                                                                                                      |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `uv run ruff check .`                                      | All checks passed                                                                                                                                                                                                                           |
| `uv run ruff format --check .`                             | 434 files already formatted (+1 vs. main; the addition is this verification record + the 6 source/test artifacts that landed across Tasks 1–7)                                                                                              |
| `uv run mypy --strict <new + modified files in this plan>` | Success: no issues found in any of: `kg_writer.py` / `agent.py` / `test_kg_writer.py` / `test_kg_loop_eval_back_compat.py` / `test_kg_loop_live_postgres.py` / `neo4j_kg.py` (bannered)                                                     |
| `uv run pytest -q`                                         | **2722 passed, 26 skipped** — vs. main's pre-plan 2709 / 23. Delta: **+13 tests** (12 mocked-unit + 1 eval-back-compat) and **+3 SKIPs** (the 3 live tests under skip-discipline when `NEXUS_LIVE_POSTGRES` is unset).                      |
| `uv run pytest packages/agents/cloud-posture/ -q`          | 80 passed, 3 skipped — including the **5 dormant `test_neo4j_kg.py` tests still green** against the now-bannered module + the 12 new `test_kg_writer.py` + the 1 new `test_kg_loop_eval_back_compat.py` + the 3 SKIP-discipline live tests. |

---

## §4. The keystone live proof — A.1-§8-style evidence

Per the discipline established by [`a1-safety-verification-2026-05-16.md`](a1-safety-verification-2026-05-16.md) §8.

```
DATE:                       2026-05-18
CI RUN URL:                 https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482
CI RUN STATUS:              completed / success
CI RUN DURATION:            2.46s (test phase) — total job: ~35s
HEAD AT RUN:                edae2b99ffcb5e8f6cc0488e2a612cbc8bf52050
WORKFLOW:                   .github/workflows/kg-loop-live.yml (committed at e50e7c2; iterated to edae2b9)
RUNNER IMAGE:               ubuntu-24.04
POSTGRES SERVICE IMAGE:     pgvector/pgvector:pg16  (Postgres 16 + pgvector preinstalled)
POSTGRES PROVISIONING:      POSTGRES_USER=nexus / POSTGRES_PASSWORD=nexus_dev / POSTGRES_DB=nexus
                            (matches docker/docker-compose.dev.yml exactly; nexus is created as
                             a superuser by initdb so the test's admin-DSN reaches the default
                             `postgres` admin DB without per-env overrides)
HEALTHCHECK:                pg_isready -U nexus (5s interval, 10 retries) — job-start gated on healthy
SCHEMA INSTALLATION:        Base.metadata.create_all(tables=[EntityModel.__table__,
                            RelationshipModel.__table__]) — see §13.2 below for why this
                            is a documented letter-vs-spirit deviation, not the
                            plan-row-6 letter (alembic upgrade head)
TESTS PASSED:               test_loop_closes_via_memory_neighbors_walk_against_real_postgres  PASSED
                            test_repeated_write_within_one_writer_yields_exactly_one_AFFECTS_edge  PASSED
                            test_skip_kg_path_does_not_touch_substrate  PASSED
TESTS XFAIL/SKIP:           none
RESULT:                     3 passed in 2.46s
OPERATOR (CI):              github-actions[bot] under PR-checks identity
```

### What this entry proves

1. **The KG read/write loop closes by execution against real Postgres.** Cloud Posture's writer wrote the asset + finding entities and the AFFECTS edge through a live `SemanticStore` against real Postgres 16; D.7's PRODUCTION `memory_neighbors_walk` (test-side imported, not D.7-side modified) seeded with the finding's entity_id returned exactly the asset external_ids Cloud Posture wrote. **Prior to this CI run the loop was asserted only by mocks** (Task 4 for the writer side, Task 5 for the report side, D.7's own tests for the walker side).

2. **The within-run REPEATED-WRITE dedup is correct against the real INSERT-only substrate.** One `KnowledgeGraphWriter` instance, two `upsert_finding(...)` calls with identical `(finding_id, affected_arns)`, then a direct query on the `relationships` table filtered to `(tenant_id, src=finding_eid, dst=asset_eid, type="AFFECTS")` returned **exactly 1 row**. This is the test the user named load-bearing on Task 3 approval; mocks (Task 4) demonstrated the agent-side dedup table behaviour, this run proves the resulting graph state against real Postgres.

3. **The skip-KG path leaves the substrate untouched.** A scan with `semantic_store=None` and a KG-tool-excluded contract produced its findings and left the `entities` + `relationships` tables empty for the test tenant. This is the lower-bound complement to Task 5's observable-output-parity gate.

### What this entry does NOT prove

- **Cross-run** AFFECTS-edge dedup. Out of scope for v0.1 per §13.1. Repeated agent runs against the same SemanticStore WILL accumulate duplicate AFFECTS edges.
- **F.5 alembic-upgrade-head against Postgres.** Out of scope due to the substrate bug at §13.2. Workaround `Base.metadata.create_all(tables=[…])` is used instead, see §13.3.
- **Multi-tenant routing on Postgres RLS.** F.4 tenant-RLS is exercised by charter's F.5 live lane (still pending its own substrate-fix plan); the KG-loop test runs single-tenant.

### Reproduction

The keystone proof is reproducible on any PR that touches the paths-filter surfaces. To reproduce locally (requires Docker + a Postgres compose service):

```bash
docker compose -f docker/docker-compose.dev.yml up -d postgres
NEXUS_LIVE_POSTGRES=1 uv run pytest \
    packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py -v
```

CI is the proof of record because it removes the per-machine variable (operator-local runs blocked twice on env-specific issues before the workflow shipped — see §13.4 process-discovery note).

---

## §5. ADR-010 conformance — re-run honestly

Per [ADR-010](decisions/ADR-010-within-agent-version-extension-template.md)'s 6-condition eligibility test for within-agent version extensions.

| #   | Condition                                     | Result               | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --- | --------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Same package                                  | **PASS**             | Every file modified is under `packages/agents/cloud-posture/` (writer, agent, callers, README, runbook, tests, integration tests) + `docs/` + `.github/workflows/`. Zero changes under any other agent's `packages/agents/<other>/`.                                                                                                                                                                                                                                                                                      |
| 2   | Additive surface — no rename/remove/repurpose | **PASS**             | Nothing removed at module/class/file level. The new `kg_writer.py` lives alongside the dormant `neo4j_kg.py`; the dormant class definition, all 3 Cypher templates, both async methods, and all 5 dormant tests stay intact. The `git log --diff-filter=D` for the dormant file returns empty across the entire plan branch sequence. **The CONDITIONAL-PASS scoped in the plan is upgraded to a clean PASS because nothing was deleted.**                                                                                |
| 3   | OCSF `class_uid` stable                       | **PASS**             | `class_uid=2003` (Compliance Finding) preserved end-to-end; the `class_uid` is one of the 6 deterministic actuals fields the Task 5 back-compat gate asserts byte-identical across the KG-off vs KG-on paths.                                                                                                                                                                                                                                                                                                             |
| 4   | F.6 audit-chain vocabulary additive           | **PASS**             | Action names `kg_upsert_asset` and `kg_upsert_finding` preserved verbatim. Only the backend implementation changes; the F.6 chain consumers (and any audit verifier) see the same vocabulary. No new audit action names.                                                                                                                                                                                                                                                                                                  |
| 5   | CLI surface unchanged                         | **PASS**             | `cli.py`'s `run-cmd` continues to default to skip-KG (`semantic_store=None`); the operator-facing behaviour is identical to pre-reroute. The only CLI-visible change is the source path of the default-None argument (`neo4j_driver=None` → `semantic_store=None`) — this is invisible to anyone invoking the CLI.                                                                                                                                                                                                        |
| 6   | Python public API params unchanged            | **CONDITIONAL PASS** | Disclosed parameter rename: `neo4j_driver: Any \| None` → `semantic_store: SemanticStore \| None`. Both keep the same shape (optional, default `None`, None → KG-skip path). Callers were updated in the same commit (`8b883c2`) — `cli.py`, `eval_runner.py`, `tests/integration/test_agent_localstack_live.py`, `tests/test_agent_unit.py` — so the in-repo surface stays internally consistent. Rename is named explicitly in the ADR-009 amendment, in PR #35's body, in §13.3 below, and here. **No silent rename.** |

**Final result: 5 PASS + 1 CONDITIONAL PASS** — matches the eligibility-test result the plan stated up-front, with condition 2 upgraded from CONDITIONAL-PASS-with-disclosed-retirement to clean PASS because the dormancy decision (Task 7) preserved everything rather than deleting it.

---

## §6. Dormancy audit — `neo4j_kg.py` and its dependency stay

Verifies the keep-don't-delete decision is structurally enforced at plan close.

| Artifact                                                            | Pre-plan state                                                               | v0.1-close state                                                                                                                                                                                | Verification                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py` | Existed (F.3 Task 6, 2026-05-08, `bee67ad`)                                  | **Exists.** DORMANT-bannered (Task 7, `547452d`). Class definition + 3 Cypher templates + 2 async methods unchanged.                                                                            | `ls -la` shows file present; `head -10` shows the banner; `grep "class KnowledgeGraphWriter"` returns the class definition; `git log --diff-filter=D -- packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py` returns **empty** across the entire plan branch sequence. |
| `packages/agents/cloud-posture/pyproject.toml` `neo4j>=5.24.0` dep  | Present (F.3 era)                                                            | **Retained.** Line 16 of `pyproject.toml`.                                                                                                                                                      | `grep "neo4j" packages/agents/cloud-posture/pyproject.toml` returns `"neo4j>=5.24.0",` at line 16.                                                                                                                                                                                   |
| `packages/agents/cloud-posture/tests/test_neo4j_kg.py`              | Existed (F.3-era, 5 tests for the writer)                                    | **Retained.** 5/5 tests still green against the now-bannered module.                                                                                                                            | `ls -la` shows file present; `uv run pytest packages/agents/cloud-posture/tests/test_neo4j_kg.py -v` returns `5 passed in 0.07s`.                                                                                                                                                    |
| Agent tool-registry pointer                                         | `kg_upsert_*` → `neo4j_kg.KnowledgeGraphWriter`                              | `kg_upsert_*` → `kg_writer.KnowledgeGraphWriter` (the new SemanticStore-backed class with the same name + signatures).                                                                          | `agent.py:51` imports from `cloud_posture.tools.kg_writer`, not `cloud_posture.tools.neo4j_kg`. Audit-chain action names (`kg_upsert_asset`, `kg_upsert_finding`) preserved verbatim.                                                                                                |
| Phase-2 swap target                                                 | Implicit (Neo4j writer existed but no document said it was the Phase-2 door) | **Explicit and labelled at two layers.** ADR-009 amendment (Task 1) labels it at the architecture-decision layer; the file's own DORMANT docstring banner (Task 7) labels it at the file layer. | Anyone opening `neo4j_kg.py` reads the banner first; anyone reading ADR-009 sees the amendment section; anyone running `git log --follow` on the file sees a clean history with no deletion gap.                                                                                     |

**Dormancy decision structurally verified.** The Phase-2 swap is "re-point the tool-registry import from `kg_writer` back to `neo4j_kg`" + a substrate-layer Neo4j swap; it is NOT "rebuild the Neo4j writer."

---

## §7. Watch-items — final audit

Three watch-items were declared at plan open. Each was verified per-task and is verified one final time at plan close, against `origin/main` (with the planned PRs #38/#39/this PR landing in sequence).

### WI-1 — `packages/charter/` UNTOUCHED end-to-end

**Held.** `git diff --stat origin/main..HEAD packages/charter/` returns empty across the entire plan branch sequence. Tasks 3 + 4 + 5 + 6 + 7 each verified this individually in their PR bodies; the aggregate at plan close is empty too. **`SemanticStore`'s public API is consumed exactly as it ships today** — no method added, no signature changed, no behaviour change. The substrate is sealed end-to-end. (The F.5 LTREE substrate bug discovered in CI is left UNFIXED in this plan per WI-1; carried forward to its own future plan — see §13.2.)

### WI-2 — NO OTHER AGENT `src/` modified

**Held.** Per-agent `git diff --stat origin/main..HEAD` returns empty for every one of: `audit`, `identity`, `investigation`, `k8s-posture`, `multi-cloud-posture`, `network-threat`, `remediation`, `runtime-threat`, `vulnerability`. The only `investigation`-related touch in the whole plan is a **test-side import** of `investigation.tools.memory_walk.memory_neighbors_walk` inside Task 6's live-proof test — a read of D.7's production function from a cloud-posture integration test. **No D.7 source code modified.**

### WI-3 — Neo4j escape-hatch door labelled at TWO layers; no deletion

**Held.** Architecture-layer labelling is in ADR-009's "Amendment 2026-05-18" section (Task 1, `d95916b`). File-layer labelling is the DORMANT docstring banner on `neo4j_kg.py` (Task 7, `547452d`). The dormant module + its dep + its 5 tests are intact at plan close. `git log --diff-filter=D --name-only origin/main..HEAD -- packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py` returns **empty** — proves no deletion happened anywhere in the plan branch sequence.

---

## §8. Back-compat preservation evidence (Task 5 eval-gate)

The plan's claim — "the reroute is additive; KG-off vs KG-on agent output is byte-identical for every shipped eval case" — is asserted by `packages/agents/cloud-posture/tests/test_kg_loop_eval_back_compat.py` (Task 5, `acd340e`).

| Dimension asserted                                    | What it pins                                                                |
| ----------------------------------------------------- | --------------------------------------------------------------------------- |
| 10 cases × 2 KG modes × 6 actuals fields              | **120 individual per-field assertions**, dict-collapsed into one pass/fail. |
| `finding_count` (report.total)                        | Count parity                                                                |
| `by_severity`                                         | Severity distribution parity                                                |
| `finding_ids` (sorted set of `finding_info.uid`)      | Every finding's identity stable                                             |
| `rule_ids` (sorted set of `compliance.control`)       | Rule mapping stable                                                         |
| `class_uids` (sorted set of `class_uid`)              | OCSF class stability (per ADR-010 condition 3)                              |
| `resource_uids` (sorted list of every `resource.uid`) | Resource identity set stable (the external_ids that land in the KG)         |

**Test passes at plan close.** Timestamps + correlation_ids are deliberately excluded — they ARE expected to differ across two separate invocations, and including them would mask real additive violations behind false-positive noise.

---

## §9. Breaking-change note

**None.** `semantic_store=None` preserves the pre-reroute observable behaviour exactly:

- `findings.json` byte-identical across the 10 eval cases (Task 5).
- `summary.md` byte-identical (same OCSF wrapping, same severity counts, same finding text).
- `audit.jsonl` action vocabulary identical (the `kg_upsert_asset` / `kg_upsert_finding` action names are preserved verbatim; only the backend differs).
- CLI surface identical (`cli.py`'s `run-cmd` still defaults to skip-KG).

The disclosed `neo4j_driver` → `semantic_store` parameter rename (ADR-010 cond 6 CONDITIONAL PASS) is the **only** API-shape change. Same shape (optional, default `None`), same semantic (`None` → KG-skip).

---

## §10. Hard scope boundary — preserved

Stated up-front in the plan; verified at plan close:

- **Zero other-agent KG writers.** Empirical (Task 2 grep audit + repeated per-task watch-item-2 checks). 0 matches outside `cloud-posture`.
- **Zero net-new entity types.** Schema is `asset` + `finding`, identical to the pre-reroute Cypher's `Asset` + `Finding` labels.
- **Zero net-new relationship types.** `AFFECTS` only, identical to the pre-reroute Cypher's `:AFFECTS` edge.
- **Zero new KG consumers.** The graph is populated by Cloud Posture and read by D.7's existing `memory_neighbors_walk`. No probability layer, no attack-path enumerator, no cure-recommendation engine.
- **No Phase-2 Neo4j swap.** The ADR-009 escape-hatch trigger (depth ≥ 4 + > 1M edges/tenant) is reaffirmed, not executed.

---

## §11. Coverage delta

| Lane                                                                                | Pre-plan (main @ Task-5-merge)             | Post-plan (this branch)                                   | Delta                             |
| ----------------------------------------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------- | --------------------------------- |
| Full repo pytest                                                                    | 2709 passed, 23 skipped                    | 2722 passed, 26 skipped                                   | **+13 passed, +3 skipped**        |
| `packages/agents/cloud-posture/` pytest                                             | 68 passed, 3 skipped (pre-Task-3 baseline) | 80 passed, 3 skipped (post-Task-7)                        | +12 passed                        |
| `packages/agents/cloud-posture/tests/test_neo4j_kg.py` (the dormant module's tests) | 5 passed                                   | **5 passed** (unchanged; against the now-bannered module) | 0 — proves dormant surface intact |

**New test files added by this plan:**

1. `tests/test_kg_writer.py` (Task 4) — 12 tests, mocked
2. `tests/test_kg_loop_eval_back_compat.py` (Task 5) — 1 test (covers 10 × 2 × 6 = 120 assertions)
3. `tests/integration/test_kg_loop_live_postgres.py` (Task 6) — 3 tests, gated by `NEXUS_LIVE_POSTGRES=1`

Sum: 13 new pytest IDs; 12 active by default + 3 SKIP-gated → **+13 passed, +3 skipped** under the default lane. Matches.

---

## §12. Reaffirmation — the new ADR rule from Task 1

**Every agent writes to the graph ONLY through `MemoryService.semantic` — no direct database drivers, ever.** This is what keeps the future Neo4j migration a one-layer swap instead of a per-agent rebuild.

This rule was implicit in ADR-009's design intent but never written down; Cloud Posture's `neo4j_kg.py` (F.3 Task 6) shipped against that absence by holding a `neo4j.AsyncDriver` directly. Task 1 wrote the rule down (ADR-009 amendment, `d95916b`). From 2026-05-18 forward:

- Any new KG-writing code (D.5, D.6, future detect agents, future supervisor primitives, future probability / attack-path consumers) must reach the graph through `MemoryService.semantic` (or one of the stores it exposes — `SemanticStore`, `EpisodicStore`, `ProceduralStore`).
- **No agent may hold a database driver instance directly** — neither `neo4j.AsyncDriver` nor `sqlalchemy.AsyncEngine` nor any other backend-specific handle.
- The dormant `cloud_posture/tools/neo4j_kg.py` is the **one and only** exception, and only because it is structurally retired (not in the tool registry, not exercised by tests except as a dormant module, retained as a marker for the Phase-2 swap path).

Code review for any new agent-side import of `neo4j`, raw `sqlalchemy.AsyncEngine`, or equivalent backend driver should reject the PR. The grep audit of Task 2 is the empirical baseline; re-running it on future PRs (the doc carries the exact invocations) catches drift at audit-time.

---

## §13. Carry-forward debts and notes

Three named, tracked follow-ups. Each is recorded **verbatim** so a future reader can act on it without re-deriving the context.

### 13.1 Cross-run AFFECTS-edge dedup is out of scope for v0.1

**(user-supplied verbatim, on Task 3 approval, 2026-05-18):**

> Cross-run AFFECTS-edge dedup is out of scope for v0.1; the graph will accumulate duplicate edges across repeated Cloud Posture runs until a future substrate-level uniqueness guarantee addresses it. This is known, accepted, and must not be silently forgotten.

**Scope of the v0.1 dedup that IS implemented:**

- Per `KnowledgeGraphWriter` instance (= per `agent.run(...)` call).
- Per `(finding_id, asset_external_id)` pair.
- Skips the `add_relationship` call when an arn is seen twice for the same finding within one writer instance.
- Asserted by `tests/test_kg_writer.py` (4 dedup tests) and proven against real Postgres by `tests/integration/test_kg_loop_live_postgres.py::test_repeated_write_within_one_writer_yields_exactly_one_AFFECTS_edge` (CI run 26055249482, GREEN).

**What v0.1 does NOT cover:**

If `agent.run(...)` fires twice against the same SemanticStore, the second run's `KnowledgeGraphWriter` instance starts with an empty dedup table and will re-emit `add_relationship` for arns the prior run already related. **The graph accumulates duplicate AFFECTS rows across runs.** This is a real defect of the v0.1 dedup boundary; it was rejected as "fix it in v0.1" because the two viable fixes both have stronger downsides than the duplicate-row noise:

1. UNIQUE constraint on `(tenant_id, src_entity_id, dst_entity_id, relationship_type)` at the SemanticStore layer — violates WI-1 (substrate sealed).
2. Read existing relationships at writer-construction time, into the agent-side dedup table — additional round-trip per finding; racy under concurrent writers; doesn't scale.

**Successor plan:** a future plan that owns substrate work will fix the cross-run case (likely path 1 above, with a migration to add the unique constraint + a backfill to dedupe existing duplicates). Until that plan lands, the graph carries v0.1 dedup-debt that grows linearly with run count per finding × per asset.

### 13.2 Charter F.5 LTREE substrate bug — real defect, future-plan-owned

**Discovered by:** CI run `26054959756` (the third of three iterations the `kg-loop-live` workflow surfaced before turning green at `26055249482`).

**The defect:** `packages/charter/src/charter/memory/models.py:106` defines `_PortableLtree.load_dialect_impl` which on the Postgres dialect calls `postgresql.LTREE()`. **SQLAlchemy 2.0.49 (this workspace's pin) does not expose a `LTREE` attribute on `sqlalchemy.dialects.postgresql`.** The F.5 `playbooks` table uses this column type, so the full F.5 alembic baseline (`0001_memory_baseline`) **cannot materialize against real Postgres** without a substrate fix.

**Why it lived undetected since F.5 v0.1:**

- aiosqlite unit tests fall through to `_PortableLtree`'s `String(512)` fallback path (line 107) — the LTREE attribute is never touched.
- Charter's own F.5 live lane (`packages/charter/tests/integration/test_memory_live_postgres.py`) **had never run in CI**. The bug was always there; nothing exercised the Postgres dialect path with a real `playbooks` table materialization.

**Why this plan did NOT fix it:**

- KG-loop-closure plan's watch-item 1 forbids any change to `packages/charter/`. The fix is a substrate change that belongs in a plan that explicitly owns charter work. Touching charter here would have invalidated the plan's hard scope boundary.

**Worked around (not fixed) in KG-loop v0.1:** see §13.3.

**Successor plan REQUIRED:**

A future "substrate maintenance" plan must:

1. Pick the right `LTREE` source — likely `sqlalchemy-utils.LtreeType`, or pin SQLAlchemy to a version that ships LTREE natively (it's not in 2.0.49; check current 2.0.x).
2. Fix `_PortableLtree.load_dialect_impl` to import from the chosen source.
3. **Get `packages/charter/tests/integration/test_memory_live_postgres.py` running green in CI.** That lane has never been green anywhere reproducible — only on operator machines with ad-hoc setup. Mirror the `.github/workflows/kg-loop-live.yml` service-container pattern from this plan.
4. Once charter's F.5 live lane is green in CI, the KG-loop test in §13.3 can optionally be retro-pointed at `alembic upgrade head` (the workaround in this plan is honestly named as a workaround; retro-pointing it is optional, not required).

**Real defect status: KNOWN, NAMED, TRACKED, NOT SILENTLY FORGOTTEN.**

### 13.3 Plan-row-6 letter-vs-spirit deviation (alembic → `Base.metadata.create_all`)

**Plan row 6 letter:** _"alembic-managed entities/relationships tables via the same fixtures the F.5 live lane uses."_

**What actually shipped** (Task 6, commit `edae2b9`): `tests/integration/test_kg_loop_live_postgres.py::_install_entities_and_relationships_schema` calls `Base.metadata.create_all(tables=[EntityModel.__table__, RelationshipModel.__table__])` against the live Postgres, installing only the two tables the KG-loop write path touches. **No `alembic upgrade head`. No `playbooks` / `episodes` / `episodes_embeddings` tables.**

**Why the deviation:** the charter F.5 LTREE substrate bug at §13.2 blocks the full F.5 alembic baseline against real Postgres. WI-1 forbids the fix here.

**Spirit honored:**

- Real Postgres (CI service container `pgvector/pgvector:pg16`), not aiosqlite, not mocks.
- Production ORM-derived schema for the two tables in scope (both production-alembic and the test read DDL from the same `EntityModel.__table__` / `RelationshipModel.__table__` definitions; the resulting schema for `entities` and `relationships` is bit-for-bit identical to production's).
- KG read/write loop closes by execution: Cloud Posture writes → live `SemanticStore` → D.7's `memory_neighbors_walk` reads the assets back via the AFFECTS edge.
- Within-run REPEATED-WRITE case proven against real INSERT-only `add_relationship`.
- Skip-KG path proven to leave substrate untouched.

**Letter deviated, named:**

- No `alembic upgrade head`. No exercise of the F.5 baseline migration against Postgres (that's blocked by §13.2 and belongs to its successor plan).
- Honestly disclosed in (a) the test's `_install_entities_and_relationships_schema` docstring, (b) the commit message at `edae2b9`, (c) PR #38's body, and (d) this verification record.

**Accepted by:** the user on Task 6/6a approval (2026-05-18), with the explicit instruction to "document it honestly in the Task 8 verification record as a found issue."

**Future-retire path:** when the successor plan in §13.2 lands the LTREE fix AND gets charter's own F.5 live lane green in CI, the KG-loop test can optionally be retro-pointed at `alembic upgrade head`. The keystone assertion the test makes (loop closes via real Postgres) doesn't change either way.

### 13.4 Process-discovery notes (non-deviations)

Recorded for posterity so future plans can reuse the patterns:

1. **CI is the keystone proof, not single-machine runs.** Two operator-local attempts blocked on env-specific issues (Docker on `$PATH`; then a stale-volume Postgres without the `nexus` role) — neither was a KG-loop code defect. CI removes the per-machine variable by always provisioning fresh from a known image. Future SAFETY-CRITICAL live proofs should ship with a corresponding CI workflow rather than relying on operator-local runs.

2. **The `kg-loop-live` workflow surfaced three bugs in sequence**, none of them in loop logic:
   - Run `26054744502`: my off-by-one in the alembic-path walk (`parents[5]` → `parents[4]`); fixed at `bf7e37d`. **Bug in my test code; CI caught it.**
   - Run `26054851092`: `ModuleNotFoundError: No module named 'psycopg2'` because charter's `_alembic_url_from` swap relied on an undeclared dep; install added at `da336cd`, then removed when §13.3 dropped alembic entirely. **CI provisioning bug.**
   - Run `26054959756`: the charter LTREE substrate bug (§13.2). **Real substrate defect; workaround at §13.3.**
   - Run `26055249482`: **3 passed in 2.46s. Keystone proof of record.**

3. **Minor plan-side test-filename discrepancy** noted at Task 7. Plan row 7 referenced `tests/test_tools_neo4j_kg.py`; actual filename is `tests/test_neo4j_kg.py` (matches the writer's module path `tools/neo4j_kg.py`). Surfaced in PR #39's body rather than silently aligned. Not a defect, just a stale plan-side reference.

---

## §14. Forward references / next-plan gate

The KG-loop closure is the **first** plan to write the SemanticStore producer side. v0.1 is intentionally narrow (Cloud Posture only); the platform's path forward depends on later plans, each named here so the next-plan gate is explicit.

| Future plan                                                                             | Purpose                                                                                                                                                            | Trigger / gate                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Substrate maintenance (LTREE fix + F.5 live lane green)                                 | Resolve §13.2; unblock alembic upgrade head against real Postgres; charter F.5 live lane goes from "shipped but unverifiable" to "shipped and CI-green."           | **Pre-requisite for any further substrate work.** Until this plan lands, charter's F.5 live lane stays latent-broken; my KG-loop test uses the workaround.                                                                                                             |
| Cross-run AFFECTS dedup (substrate UNIQUE constraint + migration + backfill)            | Resolve §13.1; the graph stops accumulating duplicate AFFECTS rows across repeated agent runs.                                                                     | After the substrate-maintenance plan above. Likely path: add UNIQUE on `(tenant_id, src_entity_id, dst_entity_id, relationship_type)`; migrate existing rows by dedupe; refactor `add_relationship` to ON-CONFLICT DO NOTHING.                                         |
| D.5 / D.6 KG-write enablement                                                           | Other detect agents start writing to `SemanticStore` for their entity types (e.g., network-threat: hosts + connections; runtime-threat: processes + signals).      | **NOT STARTED.** Each agent needs its own plan with its own ADR-010 eligibility test, its own dedup design, its own live proof. They MUST follow the rule reaffirmed at §12 (no direct database drivers; through `MemoryService.semantic` only).                       |
| KG-read consumer plans (probability layer, attack-path enumerator, cure-recommendation) | The cluster of agents that read the populated graph to produce derived findings.                                                                                   | **NOT STARTED.** D.7 already reads (via `memory_neighbors_walk`); these are the deferred consumers ADR-009 §"Consequences" names.                                                                                                                                      |
| Phase-2 Neo4j swap                                                                      | The dormant `neo4j_kg.py` becomes active again; `SemanticStore`'s session-factory switches to a Neo4j-backed session class; the platform graph runs on Neo4j Aura. | **Trigger condition reaffirmed at §12:** depth ≥ 4 + > 1M edges/tenant. Not triggered by v0.1; the graph is empty in production at v0.1 close, populated only by Cloud Posture from 2026-05-18 forward. Whether/when the trigger fires is a future-monitoring concern. |

The plan that triggers any of the above MUST re-run the Task 2 grep audit (`docs/_meta/kg-loop-task-2-grep-audit-2026-05-18.md` carries the exact invocations + expected outputs at the time of writing) to catch single-agent-invariant drift at audit-time.

---

## §15. Conclusion

v0.1 of the KG-loop closure is **complete and verified.** The keystone live proof is GREEN on CI (run `26055249482`, 3/3 passed in 2.46s). The three SAFETY-CRITICAL controls — keystone loop, within-run dedup, skip-KG isolation — all hold against real Postgres infrastructure. The dormancy decision is structurally enforced (file present, dep retained, tests retained + green, banner at two layers, zero deletion). Watch-items 1 + 2 + 3 held end-to-end. Five PASS + 1 CONDITIONAL PASS on ADR-010 conformance — matches the plan's stated eligibility-test result.

Three follow-ups are tracked, named, and recorded verbatim (§13.1, §13.2, §13.3). Two were known going in (cross-run dedup); one was discovered by CI (charter LTREE substrate bug) and one is the documented deviation from plan-row-6 letter required by the second. **None are silently forgotten.**

The new ADR rule from Task 1 — _"Every agent writes to the graph ONLY through `MemoryService.semantic` — no direct database drivers, ever"_ — is reaffirmed (§12) and is the rule code review enforces from 2026-05-18 forward.

Cross-references:

- Plan: [`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`](../superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md)
- ADR-009 (amended): [`docs/_meta/decisions/ADR-009-memory-architecture.md`](decisions/ADR-009-memory-architecture.md)
- ADR-007 (Cloud Posture as reference agent): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](decisions/ADR-007-cloud-posture-as-reference-agent.md)
- ADR-010 (within-agent-extension template): [`docs/_meta/decisions/ADR-010-within-agent-version-extension-template.md`](decisions/ADR-010-within-agent-version-extension-template.md)
- ADR-011 (PR-flow + branch protection): [`docs/_meta/decisions/ADR-011-pr-flow-discipline.md`](decisions/ADR-011-pr-flow-discipline.md)
- Task 2 grep audit: [`docs/_meta/kg-loop-task-2-grep-audit-2026-05-18.md`](kg-loop-task-2-grep-audit-2026-05-18.md)
- Keystone CI run: <https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26055249482>
- The dormant module: [`packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py) (banner at top; historical docstring beneath)
- The active writer: [`packages/agents/cloud-posture/src/cloud_posture/tools/kg_writer.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/kg_writer.py)
- The live-proof CI workflow: [`.github/workflows/kg-loop-live.yml`](../../.github/workflows/kg-loop-live.yml)
