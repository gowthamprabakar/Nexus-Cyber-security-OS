# F.7 v0.2 verification record — 2026-05-18

Final-verification gate for **F.7 v0.2 — D.7 Investigation lifecycle events on `events.>`**. Companion to the [F.7 v0.2 plan](../superpowers/plans/2026-05-17-f-7-v0-2-d-7-events-migration.md), [ADR-004](decisions/ADR-004-fabric-layer.md) (design contract), [ADR-010](decisions/ADR-010-version-extension-template.md) (within-agent-extension template — F.7 v0.2 IS the second worked example of), [ADR-011](decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) (operating discipline), and [F.7 v0.1 verification record](f-7-v0-1-verification-2026-05-17.md) (the substrate v0.2 consumes).

This record follows the **ADR-010 within-agent-extension shape** — F.7 v0.2 is a real vN→vN+1 extension of (a) F.7 v0.1's `JetStreamClient` public API and (b) D.7's existing CLI + agent-driver surface. The shape is intentionally different from F.7 v0.1's F.1/F.5/F.6 substrate-record shape (which applied only to initial versions with no prior contracts to preserve).

All 8 tasks of the F.7 v0.2 plan are committed; every pinned hash is in the [plan's execution-status table](../superpowers/plans/2026-05-17-f-7-v0-2-d-7-events-migration.md#execution-status).

**The F.7 substrate is no longer a hypothesis at the agent layer.** D.7 is the first real agent to use the F.7 v0.1 substrate, end-to-end against a real NATS broker, with all 3 lifecycle event types (`started` / `completed` / `failed`) verified by execution to reach a real subscriber with the `Nexus-Correlation-Id` header round-trip intact. Both watch-items carried through plan review are closed by execution.

---

## Gate results

| Gate                                                                        | Threshold                                                                                                                          | Result against `main` HEAD `d225c52` (post-PR-30 close)                                  |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `uv run pytest -q` (repo-wide, mocked lane; `NEXUS_LIVE_NATS` unset)        | green, no regressions vs F.7 v0.2 base                                                                                             | **2709 passed, 23 skipped**                                                              |
| D.7 mocked surface coverage (bus_emit + agent wiring + schema + eval gate)  | Per-method payload, audit-action vocabulary, non-fatal failure handling, both flag modes, byte-identical actuals across all cases  | 25 schema + 26 CLI + 19 bus_emit + 5 agent-wiring + 3 eval-both-modes = **78 new tests** |
| `NEXUS_LIVE_NATS=1 pytest .../test_bus_emit_live.py` (real broker)          | 2 tests pass: started+completed happy path; started+failed forced-exception path                                                   | **2 passed** against `nats-server v2.14.0`                                               |
| F.7 v0.1 live lane re-verified at v0.2 close (no v0.1-substrate regression) | 4 live tests still pass — v0.2 changes do not perturb v0.1's substrate behaviour                                                   | **4 passed** against same broker                                                         |
| Live-lane skip discipline (no env var)                                      | D.7 live tests SKIP with actionable reason; mocked lane stays green                                                                | ✅ (2 SKIPs from D.7's lane + 2 from F.7 v0.1's; mocked unchanged)                       |
| `ruff check .`                                                              | clean                                                                                                                              | ✅                                                                                       |
| `ruff format --check .`                                                     | clean                                                                                                                              | ✅ (430 files)                                                                           |
| `mypy` (configured `files`)                                                 | strict-clean                                                                                                                       | ✅ (213 source files)                                                                    |
| **D.7 eval suite — flag OFF (back-compat)**                                 | 10/10 with byte-identical outcomes to pre-v0.2                                                                                     | ✅ (`investigation-agent eval`: `10/10 passed`)                                          |
| **D.7 eval suite — flag ON (additive-only)**                                | 10/10; turning the bus on changes investigation outcomes by exactly zero                                                           | ✅ (`test_eval_suite_passes_10_of_10_with_flag_on`)                                      |
| **D.7 eval-actuals byte-identical between modes**                           | Per-case `actuals` dict equality across all 6 fields × all 10 cases                                                                | ✅ (`test_eval_actuals_byte_identical_between_flag_off_and_on`)                          |
| **Watch-item 1 — `packages/shared/` sealed**                                | Zero substrate diff at every implementing commit                                                                                   | ✅ HELD ACROSS ALL 7 IMPLEMENTING TASKS (see §3 below)                                   |
| **Watch-item 2 — eval-gate flag OFF AND ON**                                | Closed by execution, not assertion                                                                                                 | ✅ CLOSED at Task 6 (`d8c3e7e`)                                                          |
| **ADR-011 cadence**                                                         | 8 task PRs reported→reviewed→merged by human; agent did not merge any PR; SAFETY-CRITICAL PRs carry verified-against-HEAD sentence | ✅ (PRs #24, #25, #26, #27, #28, #29, #30 + this PR for Task 8)                          |

### Repo-wide sanity check

`uv run pytest -q` against `d225c52` (post-PR-30) → **2709 passed, 23 skipped**. **+78 mocked tests** vs the F.7 v0.2 baseline (post-PR-23 / `f2f8250`; mocked lane was 2631 passed at F.7 v0.1 close). Skip-count delta: +2 (the 2 new D.7 live tests; they SKIP without `NEXUS_LIVE_NATS=1`). Mocked-lane test budget at v0.2 close: 2631 (post-F.7-v0.1) + 78 (F.7 v0.2 additions) = 2709. No regressions in any other package's tests.

---

## §1. Live-broker evidence (Task 5 round-trip, recorded permanently)

Following the A.1 v0.1.1 §8 and F.7 v0.1 verification-record §"Live-broker evidence" disciplines. This entry is the canonical permanent record of the D.7→`events.>` proof.

| Field                                      | Value                                                                                                                                                                                                                                                    |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Broker                                     | `nats-server v2.14.0` (brew-installed locally on darwin; see §4 below for the disclosed-not-silent permanent limitation on `v2.14.0` vs the compose image's `v2.10-alpine`)                                                                              |
| Launch                                     | `nats-server -js --store_dir /tmp/nexus-nats-test-jetstream --port 4222 --http_port 8222` (mirrors F.7 v0.1 Task 1's compose-service shape — `-js` for JetStream, persistent `store_dir`, monitoring on 8222 for `/healthz`)                             |
| Readiness probe                            | `curl -sf http://localhost:8222/healthz` → `{"status":"ok"}`                                                                                                                                                                                             |
| HEAD the live run was against              | `b53de673d79128b71f01d33e7cc50afc5884c1db` (short: `b53de67`) — the Task 5 implementing commit; live lane re-run AFTER the commit landed on the branch (ADR-011 Discipline 3, against the Task-13 antecedent)                                            |
| Re-verification at v0.2 close              | `d225c52a0919e77d0f77bb467ee0183b6e9a3c39` (main HEAD post-PR-30 merge) — D.7 live lane **2 passed**, F.7 v0.1 live lane **4 passed** (no substrate regression introduced by D.7-side changes)                                                           |
| Invocation                                 | `NEXUS_LIVE_NATS=1 uv run pytest packages/agents/investigation/tests/integration/test_bus_emit_live.py -v`                                                                                                                                               |
| Result at `b53de67`                        | **2 passed in 0.32s** — full output captured in PR #28 body                                                                                                                                                                                              |
| Result at `d225c52` (v0.2 close re-verify) | **2 passed in 0.32s** — D.7 live; **4 passed in 0.31s** — F.7 v0.1 live also still green                                                                                                                                                                 |
| Mocked-lane after the live run             | `uv run pytest -q` with `NEXUS_LIVE_NATS` unset → **2709 passed, 23 skipped** (the 23 skipped are 19 pre-existing `NEXUS_LIVE_K8S` / `OLLAMA` / `POSTGRES` + 2 F.7 v0.1 Task 6 `NEXUS_LIVE_NATS` + 2 NEW from F.7 v0.2 Task 5; no silent pass-as-mocked) |

The 2 live tests, by name and what each one proves:

| #   | Test                                                                 | What it empirically demonstrates                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `test_d7_publishes_started_and_completed_against_real_broker`        | Real D.7 investigation with `publish_events_to_bus=True` → real broker persists → test-side `JetStreamClient.subscribe()` on `events.tenant.<fresh-ULID>.investigation.>` → callback fires within 10s → both `started` and `completed` events received → per-event subject + payload + `msg.headers[CORRELATION_ID_HEADER]` round-trip asserted → **same `investigation_id` ties the pair** → **all 4 filesystem artifacts also written** (the additive proof per Q8).                                                                    |
| 2   | `test_d7_publishes_failed_against_real_broker_on_pipeline_exception` | Monkeypatched `_stage_spawn` raises `RuntimeError("synthetic spawn failure for live test")` → D.7's original `RuntimeError` STILL propagates (existing failure semantics preserved) → `started` + `failed` events received on the wire → `failed` payload carries `stage="spawn"` + `error_class="RuntimeError"` + header round-trip → `started_id == failed_id` (same investigation ties them) → **NO filesystem artifacts written** (Stage-2 failure doesn't reach `_write_artifacts`; D.7's existing failure-path contract preserved). |

Together: all 3 lifecycle event types (`started` / `completed` / `failed`) proven end-to-end against a real broker.

---

## §2. Watch-item 2 closed by execution (10/10 OFF, 10/10 ON, actuals byte-identical)

Plan review carried Watch-item 2 forward verbatim:

> _"Task 6 eval-gate: 10/10 D.7 eval cases pass with flag OFF AND ON — the additive-migration proof, not softened to ON-only."_

**This watch-item is closed by execution, not by assertion.** Task 6 (PR #29, commit `d8c3e7e`) shipped **three executed tests** in `packages/agents/investigation/tests/test_eval_runner.py`:

| Test                                                           | What it asserts                                                                                                                                                                                                                                                                                |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test_eval_suite_passes_10_of_10_with_flag_off`                | 10/10 D.7 eval cases pass with the flag OFF — the back-compat half (re-pinned in this file so the verification record cites both modes from one location).                                                                                                                                     |
| `test_eval_suite_passes_10_of_10_with_flag_on`                 | 10/10 D.7 eval cases pass with the flag ON — the additive-only half. **The load-bearing flag-ON proof.**                                                                                                                                                                                       |
| **`test_eval_actuals_byte_identical_between_flag_off_and_on`** | **THE STRONGEST FORM.** Per-case `actuals` dict equality across **all 6 fields × all 10 cases** (`hypotheses_count`, `timeline_events_count`, `has_iocs`, `ioc_count`, `has_mitre_techniques`, `ocsf_class_uid`). Turning the bus on changes D.7's investigation outcomes by **exactly zero**. |

**No production code change required.** Test-boundary monkeypatch (`investigation.eval_runner.investigation_run` → closure that adds `publish_events_to_bus=True` to kwargs) + a no-broker `JetStreamClient` test double. The real `bus_emit` code path runs end-to-end (records realistic `bus_publish.success` audit entries to the chain via the real `_publish` method); the eval runner itself, the agent driver, and the substrate are all untouched.

D.7's pipeline outcomes are demonstrably independent of bus-publish side-effects. The migration is genuinely additive, not asserted-additive.

---

## §3. Watch-item 1 held across all D.7-side tasks (the structural proof)

Plan review carried Watch-item 1 forward verbatim:

> _"Task 3 must not modify packages/shared/ — D.7 only CONSUMES F.7 v0.1's public API. If any task's diff touches the shared fabric package, that is scope creep — flag it, do not merge."_

The user generalised this at PR #26 review to **all D.7-side tasks**: the substrate (`packages/shared/`) must be treated as a sealed public API the entire migration. **The structural proof the two-package concern from plan review never materialized:**

| Task | Implementing commit                      | `git diff --stat <commit>^..<commit> packages/shared/` | Held?   |
| ---- | ---------------------------------------- | ------------------------------------------------------ | ------- |
| 1    | `4c77a9c`                                | (empty)                                                | ✅ HELD |
| 2    | `b9c4c59`                                | (empty)                                                | ✅ HELD |
| 3    | `7353cfb` (SAFETY-CRITICAL)              | (empty)                                                | ✅ HELD |
| 4    | `59ea81b` (subsumption note; docs-only)  | (empty)                                                | ✅ HELD |
| 5    | `b53de67` (SAFETY-CRITICAL — live proof) | (empty)                                                | ✅ HELD |
| 6    | `d8c3e7e`                                | (empty)                                                | ✅ HELD |
| 7    | `b9170af`                                | (empty)                                                | ✅ HELD |
| 8    | this PR (docs-only)                      | (empty)                                                | ✅ HELD |

**Across all 8 commits of F.7 v0.2's execution, the substrate received zero modifications.** ADR-010 condition 1's "two-package qualification" (substrate-side `packages/shared/` + agent-side `packages/agents/investigation/`) was honored only on the agent side; the substrate side was effectively immutable from D.7's perspective.

The single edge case worth recording (process-discovery note, not a deviation): in Task 3, the shared `events_subject(tenant_id, event_type)` helper's validation regex (`^[A-Za-z0-9_-]+$`) disallows dots in a single suffix token. The plan's Q2 subject `events.tenant.<tid>.investigation.<event_type>` is a 2-segment suffix. **The bus_emit module worked around this by composing the subject as `f"{events_subject(tenant_id, 'investigation')}.{event_type}"` — using the shared helper for tenant_id validation, then appending the closed-Literal event_type token explicitly.** The alternative (modifying `packages/shared/`'s `events_subject` to accept multi-token suffixes) would have violated Watch-item 1. The chosen path keeps the substrate sealed.

This is a structural validation of the F.7 v0.1 public API contract: D.7 was able to migrate onto the bus using only the surface F.7 v0.1 shipped. No "v0.1 ships a fence, v0.2 quietly extends it" anti-pattern.

---

## §4. Permanent documented limitation — version deviation (`v2.14.0` vs `nats:2.10-alpine`)

**This is the permanent home for the version-deviation note from F.7 v0.1 §6, carried forward and re-asserted for v0.2. It is NOT runbook-only.** The runbook §2b and §8f mention the deviation for operator visibility; this section is the canonical record.

### What carried forward from F.7 v0.1 §6

F.7 v0.1 closed with a permanent documented limitation: the live-broker proof ran against `nats-server v2.14.0` (brew-installed locally) rather than the `nats:2.10-alpine` image pinned in `docker/docker-compose.dev.yml`. Reasons: the development environment didn't have Docker installed; brew was the only path to a real broker for the proof. JetStream protocol stable across NATS 2.10 / 2.11 / 2.14 — the surface exercised is the same.

### What F.7 v0.2 adds (or doesn't)

**F.7 v0.2 introduced NO new NATS-version dependency.**

The v0.2 client surface D.7 exercises is exactly the F.7 v0.1 `JetStreamClient` public API plus the `Nexus-Correlation-Id` wire-format header. No NATS feature ≥ 2.11 was used:

- `JetStreamClient.connect()` / `ensure_streams()` / `publish()` / `subscribe()` / `close()` — all NATS 2.0+ surface, all used by F.7 v0.1 already.
- `Nexus-Correlation-Id` header propagation — NATS 2.0+ message headers.
- `events.>` `StreamConfig` shape (`max_age` / `discard` / `subjects` / `retention=LIMITS` / `storage=FILE`) — all NATS 2.10-compatible per F.7 v0.1's declaration.

### What this means for production

- **The `nats:2.10-alpine` compose-image pin remains the correct production target.** Deployments running 2.10.x will work for both F.7 v0.1's substrate and F.7 v0.2's D.7 lifecycle events without any change.
- An operator running `v2.10.x` in production and `v2.14.0` locally for development sees identical observable behaviour for D.7 lifecycle publishing — the protocol surface is the same.
- The v0.2 live tests in this verification record's §1 ran on `v2.14.0`; the v0.1 §6 note about "could be reproduced on `2.10-alpine` via Docker" applies identically here.

### What future tracks should do

- **F.7 v0.3 (Cloud-Posture / D.5 / D.6 migrations onto `findings.>`):** re-confirm at v0.3 plan-write time that no NATS feature ≥ 2.11 is introduced by the finding-publish path. If the OCSF envelope on `findings.>` ever requires a 2.11+ broker feature, bump the compose pin AND re-record this section.
- **Production hardening:** pin the docker-compose image to a specific 2.10.x patch release for reproducibility, or move to a tag that bundles 2.10.x security patches automatically.
- **CI integration** (if the live lane ever runs in CI): use the docker-compose image directly to eliminate the version gap permanently.

---

## §5. Hard scope boundary — preserved exactly

The F.7 v0.2 plan's hard scope boundary, restated verbatim and preserved through every task:

**F.7 v0.2 = D.7 lifecycle events onto `events.>` ONLY.**

The plan's "three knobs locked" framing held empirically:

| Knob                                        | Status at v0.2 close                                                                                                                                                            |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **One agent** — D.7 only                    | ✅ Held. No code under `packages/agents/cloud-posture/` / `network-threat/` / `runtime-threat/` was touched. Other detect agents continue to write filesystem artifacts.        |
| **One direction** — publish-side only       | ✅ Held. D.7 publishes lifecycle events; no D.7 subscriber-side code lands in v0.2. `find_related_findings` continues to read sibling-agent workspaces via the filesystem path. |
| **One event-class** — lifecycle events only | ✅ Held. D.7's `incident_report.json` (OCSF `class_uid` 2005) continues to be written to the charter workspace; NOT migrated to `findings.>`.                                   |

Explicitly out-of-scope items, each named and verified-not-present at v0.2 close:

- **Cloud-Posture migration** onto `findings.>` → F.7 v0.3+, separate plan, **not started**. No code under `packages/agents/cloud-posture/src/` touched.
- **D.5 (Network Threat) migration** → F.7 v0.3+, separate plan, **not started**. No code under `packages/agents/network-threat/src/` touched.
- **D.6 (Runtime Threat) migration** → F.7 v0.3+, separate plan, **not started**. No code under `packages/agents/runtime-threat/src/` touched.
- **D.7's `find_related_findings` sibling-reads onto `findings.>`** → later v0.x. The filesystem path is unchanged at `packages/agents/investigation/src/investigation/tools/related_findings.py`.
- **D.7's `incident_report.json` (OCSF 2005) finding-publish onto `findings.>`** → later v0.x. `_write_artifacts` in `agent.py` still writes the JSON file to the charter workspace.
- **Any new D.7 detection capability** → none. No new sub-investigations, no new stage logic, no new MITRE techniques, no LLM-prompt changes. The 6-stage pipeline (`SCOPE` → `SPAWN` → `SYNTHESIZE` → `VALIDATE` → `PLAN` → `HANDOFF`) is unchanged structurally; the agent driver gains only conditional `bus_emit` invocations at Stage-1 entry + Stage-6 exit + a `try/except` wrapping Stages 2-6.
- **Edge-plane leaf-node** → E.1 + E.2 scope, separate plans, **not started**.

Zero agents under v0.3+ scope have been touched. The next plan's surface starts from the same baseline F.7 v0.2 inherited.

---

## §6. Process notes — F.7 v0.2 executed clean under ADR-011

Recording honestly, in source-of-truth form, so future plans inherit the history rather than rediscover it. Same self-documenting-history discipline as A.1 v0.1.1's four-boundary notes and F.7 v0.1's "two disclosed deviations" record.

### Smooth execution under ADR-011's discipline

F.7 v0.2 is the second plan to execute end-to-end under [ADR-011](decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) (F.7 v0.1 was the first). All 8 task PRs operated under all four ADR-011 disciplines from PR-open without exception:

- **Discipline 1 (labelling at PR-open).** Every PR declared its risk label in the first line of the body. **6 LOW-RISK** (Tasks 1, 2, 4, 6, 7, 8) and **2 SAFETY-CRITICAL** (Tasks 3, 5) per the plan's flagging. The reviewer did not override any label. Two labels were specifically reviewed for upgrade-risk and confirmed at LOW-RISK: Task 2's flag wiring (no publish behaviour wired through; the user's upgrade trigger explicitly checked and NOT fired) and Task 6's eval-gate (no production code change; the user's upgrade trigger explicitly checked and NOT fired).
- **Discipline 2 (branch protection).** All merges went through the protected path on `main`. `bypass_actors: []` was structurally enforced via `.github/branch-protection.json`. No direct-to-main pushes.
- **Discipline 3 (verified-against-HEAD sentence).** The 2 SAFETY-CRITICAL PRs (#26 for Task 3, #28 for Task 5) each carried the sentence: short hash, full hash, gates-run-AFTER-commit phrasing, clean `git status --short`. Each was written explicitly against the Task-13 antecedent (editor-only fix that never reached the commit).
- **Discipline 4 (report → review → merge, agent does not merge).** All 8 task PRs were reported and then merged by the human reviewer. The agent did not merge any PR.

### Three process-discovery notes (not deviations)

F.7 v0.2 ran clean — **zero process failures** (no editor-only fixes that never reached a commit, no direct-to-main pushes, no live tests merged on assertion, no scope creep). Three small process-discovery notes worth recording for completeness, none of which represent a deviation from the plan's intent:

**(a) Task 4 subsumed by Task 3.** Plan row 4 originally scoped "~10-15 unit tests for `bus_emit`". Task 3 already shipped 19 `bus_emit` unit tests + 5 agent-wiring tests = 24 mocked tests covering the same surface. The user's directive at PR #26 review ("if Task 4's coverage is already subsumed, say so and collapse it into a short confirmation/plan-status note rather than inventing redundant tests. Report reality over plan-conformance.") was followed: Task 4's PR (#27, commit `59ea81b`) was a docs-only subsumption note with a per-plan-row-4-requirement citation map. No padding of redundant tests. This is **reality-over-plan-conformance**, the same discipline F.7 v0.1's record documented for its own deviations.

**(b) Subject builder used in two steps to honor Watch-item 1.** The shared `events_subject(tenant_id, event_type)` helper's validation regex (`^[A-Za-z0-9_-]+$`) disallows dots in a single suffix token. The plan's Q2 subject `events.tenant.<tid>.investigation.<event_type>` is a 2-segment suffix that the single-token helper cannot build directly. The bus_emit module in Task 3 composed the subject as `f"{events_subject(tenant_id, 'investigation')}.{event_type}"` — using the helper for tenant_id validation, appending the closed-Literal event_type token explicitly. The alternative (modifying `packages/shared/`'s `events_subject` to accept multi-token suffixes) would have violated Watch-item 1. The chosen path keeps the substrate sealed and was explicitly disclosed in PR #26's body. This is a **structural validation of the v0.1 public API surface** — D.7 worked around the constraint without leaking changes into the substrate.

**(c) Task 6's flag-ON exercise via test-boundary injection.** Plan row 6 said "run `investigation-agent eval ...` with the flag ON in the env". A literal reading would require either modifying the CLI's `eval` subcommand to accept the flag OR modifying the `InvestigationEvalRunner` to read the env var. **Both would be production-code changes.** The user's directive at PR #28 review ("LOW-RISK by plan IF it is purely an eval-runner exercise with no code change — if Task 6 modifies any D.7 production code, upgrade it and STOP") made this an explicit guardrail. Task 6's implementation honored this guardrail via **test-boundary monkeypatch**: `monkeypatch.setattr(investigation.eval_runner, "investigation_run", _flag_on_run)` injects the flag at the agent-call boundary. The eval runner itself, the CLI, and the agent driver were all unchanged. This is **stricter than the plan's letter and matches its spirit** (additive-only proof). Disclosed explicitly in PR #29's body.

None of these are deviations from D.7's behaviour or the F.7 v0.2 plan's hard scope. All three were transparently disclosed at PR time. **F.7 v0.2 ships clean.**

---

## §7. Per-task surface

Pinned in the [plan's execution-status table](../superpowers/plans/2026-05-17-f-7-v0-2-d-7-events-migration.md#execution-status) with full per-task notes. Headline-level summary:

| Task | Commit    | PR  | Risk label          | Headline                                                                                                                                                                                                                                                                                                                    |
| ---- | --------- | --- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `4c77a9c` | #24 | LOW-RISK            | `InvestigationLifecycleEvent` pydantic schema + `LifecycleEventType` Literal alias + cross-field invariant + deterministic `to_payload_bytes()` + 25 schema tests.                                                                                                                                                          |
| 2    | `b9c4c59` | #25 | LOW-RISK            | `--publish-events-to-bus / --no-publish-events-to-bus` paired flag on both `run` + `triage`; `NEXUS_FABRIC_PUBLISH=1` env-var fallback (CLI wins); agent.run kwarg added (stored, NOT branched on); 26 wiring tests. **Upgrade trigger NOT fired.**                                                                         |
| 3    | `7353cfb` | #26 | **SAFETY-CRITICAL** | `bus_emit.py` (NEW): `BusEmitter` class + 3 additive audit-action constants + non-fatal `_publish()` core; Stage-1/6 wiring + try/except around Stages 2-6 + finally-close; 19 unit tests + 5 agent-wiring tests incl. the load-bearing `test_run_continues_when_bus_publish_fails`.                                        |
| 4    | `59ea81b` | #27 | LOW-RISK            | Subsumption note: Task 3 already shipped Task 4's plan-row coverage. Doc-only plan-status update with per-requirement citation map. No padding of redundant tests (reality over plan-conformance).                                                                                                                          |
| 5    | `b53de67` | #28 | **SAFETY-CRITICAL** | Live NATS round-trip integration test at `tests/integration/test_bus_emit_live.py`. 2 tests covering all 3 lifecycle event types (`started` + `completed` happy path; `started` + `failed` forced exception). All 3 prove `Nexus-Correlation-Id` header round-trip + 4 filesystem artifacts still written (additive proof). |
| 6    | `d8c3e7e` | #29 | LOW-RISK            | Both-modes eval-gate: 10/10 OFF + 10/10 ON + per-case actuals byte-identical across all 6 fields × 10 cases. **Closes Watch-item 2 by execution.** No production code change (test-boundary monkeypatch injection).                                                                                                         |
| 7    | `b9170af` | #30 | LOW-RISK            | Runbook addendum: `docs/runbooks/fabric.md` §8 D.7 lifecycle events on the wire. 7 sub-sections covering enable + event types + non-fatal semantics + sample subscriber + reproduce-the-proof + version carryover + D.7-related deferments.                                                                                 |
| 8    | _this PR_ | TBD | LOW-RISK            | This record (closes F.7 v0.2).                                                                                                                                                                                                                                                                                              |

2 of 8 implementing PRs (#26 for Task 3, #28 for Task 5) were SAFETY-CRITICAL per the plan's flag and carried the verified-against-HEAD sentence in their PR bodies — naming the short hash, full hash, gates-run-AFTER-commit phrasing, and clean `git status --short` claim.

---

## §8. ADR-010 conformance check — re-confirmed at execution time

The plan's ADR-010 six-condition test was run honestly at plan-write time with all six PASS. **Re-confirmed at execution time (i.e., against the actually-shipped v0.2 surface, not just the planned surface):**

| #   | Condition                                         | Result at `d225c52` (v0.2 close)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Same package directory as the prior version       | **PASS — single-package in practice.** Plan-write-time stated "two-package qualification" (substrate + agent). Watch-item 1 held empirically across all 7 implementing tasks — **`packages/shared/` zero diff every time**. The "substrate-side" cell of the two-package shape was never used. Execution-time shape is effectively single-package (agent-side only).                                                                                                                                                    |
| 2   | Additive surface — no rename / remove / repurpose | **PASS.** New: `investigation/bus_emit.py` module + `BusEmitter` class + 3 `BUS_PUBLISH_*_ACTION` constants + `mint_investigation_id()` + `InvestigationLifecycleEvent` + `LifecycleEventType` + `CORRELATION_ID_HEADER` reference + `PUBLISH_FLAG_ENV_VAR` constant + `_resolve_publish_flag` helper + `--publish-events-to-bus / --no-publish-events-to-bus` CLI flag on 2 existing subcommands + `publish_events_to_bus: bool = False` kwarg on `agent.run`. **No existing symbol renamed, removed, or repurposed.** |
| 3   | OCSF `class_uid` unchanged                        | **PASS.** v0.2 publishes lifecycle events to `events.>` (non-OCSF; arbitrary bytes per F.7 v0.1's Q5). `IncidentReport.OCSF_CLASS_UID = 2005` unchanged. `to_ocsf()` method unchanged.                                                                                                                                                                                                                                                                                                                                  |
| 4   | F.6 audit-chain action vocabulary additive only   | **PASS — verified by execution.** 3 new types under `investigation.bus_publish.*` namespace; no existing charter action (`invocation_started` / `invocation_completed` / `invocation_failed` / `tool_call` / `output_written`) was renamed or repurposed. Test `test_audit_action_constants_are_additive_per_adr_010_cond_4` pins the new strings. The audit chain's existing entries still appear in D.7's `audit.jsonl` exactly as before.                                                                            |
| 5   | CLI subcommand surface unchanged                  | **PASS.** `investigation-agent` has the same 3 subcommands (`eval`, `run`, `triage`). The new flag is OPTIONAL on `run` + `triage` with a safe default (`None` → resolved to `False`). Existing operator workflows are unchanged when the flag is not opted in. The `eval` subcommand is unmodified (Task 6's flag-ON exercise was via test-boundary monkeypatch — see §6(c)).                                                                                                                                          |
| 6   | Python public API params unchanged                | **PASS.** `investigation.agent.run` gained `publish_events_to_bus: bool = False` — optional kwarg with safe default. `investigation.cli.run_cmd` / `triage_cmd` gained the same. `JetStreamClient` methods (`connect` / `ensure_streams` / `publish` / `publish_finding` / `subscribe` / `close`) — **unchanged** (verified by Watch-item 1's empirical hold). No existing param renamed, removed, or repurposed.                                                                                                       |

**All six conditions PASS at execution time.** F.7 v0.2 is the second worked example of ADR-010 (after A.1 v0.1.2 CLI promotion wiring). It validates ADR-010's framework empirically: the additive-surface contract was honored across 8 commits with no escape valves.

---

## §9. Coverage delta vs F.7 v0.2 baseline

Cumulative `git diff --stat` from `f2f8250` (the F.7 v0.2 plan-PR merge commit, v0.2 base) to `d225c52` (`main` HEAD after Task 7 closes):

| File                                                                                     | Δ LOC                                      |
| ---------------------------------------------------------------------------------------- | ------------------------------------------ |
| `packages/agents/investigation/src/investigation/bus_emit.py` (NEW)                      | +271                                       |
| `packages/agents/investigation/src/investigation/agent.py` (Stage-1/6 wiring)            | +166 / −55                                 |
| `packages/agents/investigation/src/investigation/cli.py` (flag wiring)                   | +56                                        |
| `packages/agents/investigation/src/investigation/schemas.py` (lifecycle schema)          | +75 / −1                                   |
| `packages/agents/investigation/tests/integration/__init__.py` (NEW, empty)               | 0                                          |
| `packages/agents/investigation/tests/integration/test_bus_emit_live.py` (NEW)            | +469 / 2 live tests                        |
| `packages/agents/investigation/tests/test_agent.py` (5 new wiring tests)                 | +336                                       |
| `packages/agents/investigation/tests/test_bus_emit.py` (NEW)                             | +392 / 19 unit tests                       |
| `packages/agents/investigation/tests/test_cli.py` (26 new flag-wiring tests)             | +306                                       |
| `packages/agents/investigation/tests/test_eval_runner.py` (3 both-modes)                 | +166                                       |
| `packages/agents/investigation/tests/test_schemas.py` (21 schema tests)                  | +298                                       |
| `docs/runbooks/fabric.md` (§8 D.7 lifecycle events)                                      | +149                                       |
| `docs/superpowers/plans/2026-05-17-f-7-v0-2-d-7-events-migration.md` (status-table pins) | +20 / −12 (net +8 across hash-pin updates) |
| **Total**                                                                                | **+2648 inserts, −56 deletes**             |

| Test surface                                              | Pre-v0.2 baseline | After v0.2 close | Δ                              |
| --------------------------------------------------------- | ----------------- | ---------------- | ------------------------------ |
| Repo-wide mocked lane (`pytest -q` passed)                | 2631              | 2709             | **+78**                        |
| Repo-wide skipped (gated lanes)                           | 21                | 23               | +2 (the 2 new D.7 live tests)  |
| D.7 schema surface (`test_schemas.py`)                    | 42                | 67               | +25 (lifecycle-event schema)   |
| D.7 CLI surface (`test_cli.py`)                           | 7                 | 33               | +26 (flag wiring)              |
| D.7 agent-driver surface (`test_agent.py`)                | 9                 | 14               | +5 (F.7 v0.2 wiring tests)     |
| D.7 bus_emit surface (`test_bus_emit.py`) (NEW)           | 0                 | 19               | +19                            |
| D.7 eval-runner surface (`test_eval_runner.py`)           | 15                | 18               | +3 (both-modes gate)           |
| D.7 live lane (`tests/integration/test_bus_emit_live.py`) | 0                 | 2                | +2 (`NEXUS_LIVE_NATS=1`-gated) |

No regressions in any other package's tests.

---

## §10. Back-compat preservation + additive-only evidence

The plan's reversibility-and-rollback section made two claims this verification record empirically demonstrates:

| Claim                                                                           | Evidence at v0.2 close                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Back-compat — flag OFF preserves pre-v0.2 D.7 behaviour byte-identically.**   | Test `test_eval_suite_passes_10_of_10_with_flag_off` (10/10 cases) + `test_run_with_flag_off_does_not_construct_bus_emitter` (NO `BusEmitter` constructed when flag is OFF — monkeypatched stub raises `AssertionError` on construction; passes when flag is OFF). When operators don't opt in, D.7's code path makes ZERO NATS-related calls. |
| **Additive-only — flag ON changes investigation outcomes by exactly zero.**     | Test `test_eval_actuals_byte_identical_between_flag_off_and_on` (per-case `actuals` dict equality across all 6 fields × all 10 cases). The bus path is an audit-chain side-effect; D.7's pipeline outputs (`hypotheses`, `timeline`, `iocs`, `mitre_techniques`, OCSF envelope) are unperturbed.                                               |
| **Non-fatal — broken bus does not break D.7.**                                  | Test `test_run_continues_when_bus_publish_fails` (mocked) + the live-lane Test-2's "D.7's existing failure semantics preserved" assertions (real broker). When the bus is unreachable, `bus_publish.failure` lands on the F.6 chain, the investigation continues, and the 4 filesystem artifacts are still written.                            |
| **Rollback — `--no-publish-events-to-bus` disables even when env says enable.** | Test `test_resolve_publish_flag_cli_false_overrides_env_true` + the end-to-end version `test_run_cli_no_flag_overrides_env_true` (env var set + `--no-publish-events-to-bus` on CLI → `agent.run` gets `publish_events_to_bus=False`). Operators with the env var set globally can still disable per-invocation.                               |

---

## §11. Breaking-change note

**None.** F.7 v0.2 adds new optional surface only:

- `--publish-events-to-bus` / `--no-publish-events-to-bus` flag — default `False` (off).
- `NEXUS_FABRIC_PUBLISH=1` env var — also defaults to off.
- `investigation.agent.run(..., publish_events_to_bus: bool = False)` — optional kwarg with safe default.
- 3 new audit-action types — additive to D.7's chain vocabulary.

Operators not opting in see byte-identical pre-v0.2 D.7 behaviour. The 10/10 flag-OFF eval-gate verifies this. Existing automation / scripts / runbooks need no changes.

**F.7 v0.3+ (Cloud-Posture / D.5 / D.6 finding-publish migrations)** will run ADR-010's eligibility test against F.7 v0.2 as the prior version when each plan opens — at that point F.7 has TWO prior version surfaces (v0.1's `JetStreamClient` + v0.2's D.7 lifecycle events) that v0.3 must preserve under the additive-surface invariant.

---

## §12. What F.7 v0.2 unblocks (forward references)

After this record closes, the following plans become straightforwardly shippable because D.7's migration proves the substrate works with a real agent:

| Future plan                                                 | What it now builds on (with D.7 as the existence proof)                                                                                                                                                                   |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F.7 v0.3 — Cloud-Posture finding-publish onto `findings.>`  | Pattern is now known. The `BusEmitter`-shaped helper + opt-in CLI flag + non-fatal failure handling + Stage-1/Stage-6-style emit-points + audit-action vocabulary extension can all be templated from D.7's v0.2 surface. |
| F.7 v0.4+ — D.5 / D.6 finding-publish migrations            | Same template. Each detect agent gets its own v0.x plan with its own ADR-010 eligibility test against F.7 v0.2 as the new prior baseline.                                                                                 |
| Later F.7 v0.x — D.7 sibling-finding consumer migration     | Once Cloud-Posture / D.5 / D.6 publish to `findings.>`, D.7 can stop reading sibling-workspaces from the filesystem and switch to subscribing. This is the natural follow-on to F.7 v0.3+.                                |
| Later F.7 v0.x — D.7 `incident_report.json` finding-publish | D.7 emits an incident-finding to the filesystem today; the bus migration onto `findings.>` is structurally identical to Cloud-Posture's v0.3 pattern.                                                                     |
| Later — S.1 Console real-time activity feed                 | The 3 D.7 lifecycle events are now actually published on `events.>` with a stable per-tenant subject. S.1 Console can subscribe immediately.                                                                              |
| Later — A.4 Meta-Harness                                    | The `audit.>` stream still has no producer (D.7's audit chain stays on the F.6 chain-file). A.4 needs the agents to migrate their audit emission onto `audit.>` in a future v0.x.                                         |

None of these happen in v0.2. Each gets its own plan with its own ADR-010 eligibility test.

---

## §13. Immediate next-plan gate

**F.7 v0.3 — Cloud-Posture finding-publish migration onto `findings.>`.**

This is the first agent-side finding-publish migration. The plan, when authored, must:

1. **Run and record ADR-010's six-condition eligibility test** against F.7 v0.2 as the prior version. The two prior public-API surfaces (the F.7 v0.1 `JetStreamClient` + v0.2's D.7 lifecycle-event shape) must both be preserved under the additive-surface invariant.
2. **State the hard scope boundary** in the same shape as F.7 v0.2's plan: one agent (Cloud-Posture only), one direction (publish-side only), one event-class (findings — the OCSF v1.3 envelope on `findings.>`). NOT D.5, NOT D.6, NOT D.7's `find_related_findings` consumer migration. Each remaining agent migration gets its own v0.x.
3. **Carry forward the additive + reversible discipline:** Cloud-Posture's filesystem path (the existing `findings.json` write) must remain intact in v0.3; the bus path is opt-in behind a switch with non-fatal failure semantics.
4. **Re-run the `NEXUS_LIVE_NATS=1` lane** to prove the Cloud-Posture migration end-to-end against a real broker. Same A.1-live-cluster-grade discipline as F.7 v0.1 Task 6 and F.7 v0.2 Task 5.
5. **Address any NATS-version dependency that exceeds 2.10.** Re-confirm in the plan that no 2.11+ broker feature is used; if any is required (unlikely — `findings.>` uses the same surface), bump the compose pin AND re-record §4 of this verification record (carry the v2.14.0/2.10-alpine note forward + update if the baseline changes).
6. **Eval-gate exercise both flag modes** for Cloud-Posture's own eval cases (same shape as v0.2's Task 6 — byte-identical actuals across flag OFF and ON).

F.7 v0.3 is **not started**. No Cloud-Posture branch exists, no plan doc written, no commits made.

Other v0.4+ candidates (D.5 / D.6 migrations onto `findings.>`) are deferred until v0.3 lands; each gets its own plan and its own ADR-010 eligibility test.

---

## Sign-off

F.7 v0.2 closes with D.7's migration **empirically proven against a real NATS broker**. The 2 live tests prove all 3 lifecycle event types reach a real subscriber with the `Nexus-Correlation-Id` header round-trip intact. The 78 mocked tests prove the contract per-method. The hard scope boundary is preserved exactly: one agent, one direction, one event-class — three knobs locked, all three held.

**Watch-items closed:**

- **Watch-item 1** (substrate sealed) — HELD ACROSS ALL 7 IMPLEMENTING TASKS by empirical diff-stat audit. The substrate is treated as a sealed public API end-to-end.
- **Watch-item 2** (eval-gate both modes) — CLOSED AT TASK 6 BY EXECUTION. 10/10 flag OFF + 10/10 flag ON + per-case actuals byte-identical across 6 fields × 10 cases.

**Version-deviation note** (`v2.14.0` vs `nats:2.10-alpine`) carried forward from F.7 v0.1 §6 and re-asserted with the explicit "F.7 v0.2 introduced NO new NATS-version dependency" statement. The compose-image pin remains the correct production target.

**F.7 v0.2 executed clean.** Zero process failures. Three small process-discovery notes recorded honestly (Task 4 subsumption, subject builder two-step composition, Task 6 test-boundary injection) — none represent deviations from D.7's behaviour or the F.7 v0.2 plan's hard scope.

The F.7 substrate is now demonstrably useful to a real agent. F.7 v0.3 (Cloud-Posture finding-publish migration) starts from a flat-tested foundation when it begins.

— recorded 2026-05-18 (F.7 v0.2, D.7 lifecycle-events plan close)
