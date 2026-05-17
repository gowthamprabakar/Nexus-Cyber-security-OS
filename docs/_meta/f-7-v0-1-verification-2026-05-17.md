# F.7 v0.1 verification record — 2026-05-17

Final-verification gate for **F.7 v0.1 — Fabric runtime (NATS JetStream live)**. Companion to the [F.7 v0.1 plan](../superpowers/plans/2026-05-17-f-7-v0-1-fabric-runtime.md), [ADR-004](decisions/ADR-004-fabric-layer.md) (design contract), and [ADR-011](decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) (operating discipline).

This record follows the **F.1/F.5/F.6 substrate-record shape** — not [ADR-010](decisions/ADR-010-version-extension-template.md)'s within-agent-extension shape — because F.7 v0.1 is an **initial version of a new substrate component**, not a vN→vN+1 extension. ADR-010's eligibility test was executed in the plan and recorded as N/A or trivially satisfied across all six conditions (no prior version's contracts to preserve).

All 8 tasks of the F.7 v0.1 plan are committed; every pinned hash is in the plan's execution-status table.

**This is the load-bearing substrate every cross-agent-correlation feature inherits.** The supervisor/delegation primitive, A.4 Meta-Harness on `audit.>` and `events.>`, D.7 v0.2 cross-incident graph queries on `findings.>`, S.1 Console real-time activity feed, E.1 edge plane's central-side endpoint — each gets shorter and stronger because F.7 v0.1 is underneath.

---

## Gate results

| Gate                                                                         | Threshold                                                                                                                                      | Result                                                          |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `uv run pytest -q` (repo-wide, mocked lane; `NEXUS_LIVE_NATS` unset)         | green, no regressions vs F.7 base                                                                                                              | **2631 passed, 21 skipped**                                     |
| Mocked client surface coverage                                               | `test_fabric_client.py` covers Q1-Q7 paths for all six public methods + 3 typed exceptions                                                     | **53 tests** (28 Task-3 + 6 Task-4 + 19 Task-5)                 |
| Mocked stream surface coverage                                               | every `StreamSpec` instance asserts ADR-004 retention/subjects/ordering                                                                        | **36 tests** parameterized over 5 streams                       |
| `NEXUS_LIVE_NATS=1 uv run pytest …/test_fabric_client_live.py` (real broker) | 4 tests pass including header round-trip                                                                                                       | **4 passed** against `nats-server v2.14.0`                      |
| Live-lane skip discipline (no env var)                                       | all 4 SKIP with actionable reason; mocked lane stays green                                                                                     | ✅ (4 skipped, mocked unchanged)                                |
| `ruff check .`                                                               | clean                                                                                                                                          | ✅                                                              |
| `ruff format --check .`                                                      | clean                                                                                                                                          | ✅ (426 files)                                                  |
| `mypy` (configured `files`)                                                  | strict-clean                                                                                                                                   | ✅ (212 source files)                                           |
| **Bus property — every message carries `Nexus-Correlation-Id`**              | `publish()` resolves from kwarg → contextvar → raise BEFORE network call                                                                       | ✅ (Task 4; 6 Q3-path tests in mocked, 1 in live)               |
| **Header propagation on the wire**                                           | `msg.headers["Nexus-Correlation-Id"]` reaches the consumer for arbitrary streams (not just findings.>)                                         | ✅ (Task 6 live test 2)                                         |
| **`ensure_streams()` idempotent + drift-detecting**                          | second call no-ops; broker drift on subjects/max_age/discard raises `StreamSpecMismatchError`; client never overwrites                         | ✅ (Task 3 mocked + Task 6 live test 1)                         |
| **OCSF v1.3 envelope enforced on `findings.>`**                              | `publish_finding()` wraps via `NexusEnvelope`; rejects non-findings subjects; JSON-encoding deterministic                                      | ✅ (Tasks 3+4 mocked + Task 6 live test 4)                      |
| **ADR-011 cadence**                                                          | 7 task PRs all reported → reviewed → merged by human; agent did not merge any PR; 3 SAFETY-CRITICAL PRs carried verified-against-HEAD sentence | ✅ (PRs #15, #16, #17, #18, #19, #20, #21 + this PR for Task 8) |

### Repo-wide sanity check

`uv run pytest -q` against `main` HEAD `ad5e512` (post-PR-21 merge) → **2631 passed, 21 skipped**. **+89 mocked tests** vs the F.7 v0.1 baseline (`44ab257`, the plan-PR merge commit) plus **+4 live-lane tests** that SKIP cleanly without `NEXUS_LIVE_NATS=1`. Skip-count delta: +4 (the 4 new live tests). No regressions in any other package's tests.

---

## Live-broker evidence (Task 6 round-trip, recorded permanently)

Following the A.1 v0.1.1 §8 live-entry discipline. This entry is the canonical record of the live-broker proof of the F.7 v0.1 substrate; future operators reproducing the proof should match this shape.

| Field                          | Value                                                                                                                                                                                                             |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Broker                         | `nats-server v2.14.0` (brew-installed locally on darwin; see §"Permanent documented limitation — version deviation" below for the disclosed-not-silent note on `v2.14.0` vs the compose image's `v2.10-alpine`)   |
| Launch                         | `nats-server -js --store_dir /tmp/nexus-nats-test-jetstream --port 4222 --http_port 8222` (mirrors Task 1's compose-service shape: JetStream enabled, persistent store_dir, monitoring on 8222 for `/healthz`)    |
| Readiness probe                | `curl -sf http://localhost:8222/healthz` → `{"status":"ok"}`                                                                                                                                                      |
| HEAD the live run was against  | `f84a22fd158773822ebdeb847ed5c61d01176022` (short: `f84a22f`) — the Task 6 implementing commit; live lane re-run AFTER the commit landed on the branch (ADR-011 Discipline 3, against the Task-13 antecedent)     |
| Invocation                     | `NEXUS_LIVE_NATS=1 uv run pytest packages/shared/tests/integration/test_fabric_client_live.py -v`                                                                                                                 |
| Result                         | **4 passed in 0.42s** — full output captured in PR #20 body                                                                                                                                                       |
| Mocked-lane after the live run | `uv run pytest -q` with `NEXUS_LIVE_NATS` unset → **2631 passed, 21 skipped** (the 4 live tests SKIP cleanly with an actionable reason naming the env var + the canonical `docker compose up -d nats` invocation) |

The 4 live tests, by name and what each one proves:

| #   | Test                                                                  | What it empirically demonstrates                                                                                                                                                                                                                                                                                                                                                               |
| --- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `test_connect_and_ensure_streams_against_real_broker`                 | All 5 ADR-004 streams created on real broker; per-stream `js.stream_info()` confirms name + subjects + max_age match `StreamSpec`; second `ensure_streams()` call no-ops (Q2 idempotency).                                                                                                                                                                                                     |
| 2   | **`test_publish_subscribe_round_trip_carries_correlation_id_header`** | **The load-bearing one.** Publish payload + correlation_id through `JetStreamClient` → real broker persists → real subscribe → callback fires within 5s → payload bytes match exactly → `msg.headers[CORRELATION_ID_HEADER]` equals the published correlation_id. The 4 prongs (publish→real broker / real subscribe / callback fires / payload+header correct) are all asserted by execution. |
| 3   | `test_contextvar_correlation_id_propagates_to_header_live`            | Q3 path (b) on the wire: caller wraps `publish()` in `with correlation_scope(<id>):` with no explicit kwarg; ambient id still reaches the wire-level `Nexus-Correlation-Id` header on the received message. Mocked equivalent (`test_publish_falls_back_to_contextvar_when_kwarg_absent`) was necessary but not sufficient; this proves the contextvar → header plumbing end-to-end.           |
| 4   | `test_publish_finding_round_trip_against_real_broker`                 | `publish_finding()`'s envelope-wrap + deterministic JSON encode reaches the wire intact. Received payload deserialises to the wrapped OCSF + `nexus_envelope` sub-dict (all 6 envelope fields present) AND the header carries the envelope's `correlation_id`.                                                                                                                                 |

---

## Per-task surface

Pinned in the [F.7 v0.1 plan's execution-status table](../superpowers/plans/2026-05-17-f-7-v0-1-fabric-runtime.md#execution-status) with full per-task notes. Headline-level summary:

| Task | Commit    | PR  | Risk label          | Notes                                                                                                                                                                                                                                        |
| ---- | --------- | --- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `af061e6` | #15 | LOW-RISK            | Hardened the pre-existing `nats` service in `docker/docker-compose.dev.yml`: `--store_dir /data`, persistent bind-mount, healthcheck on `:8222/healthz`.                                                                                     |
| 2    | `de5fff4` | #16 | LOW-RISK            | `streams.py` — `StreamSpec` frozen dataclass + 5 instances matching ADR-004 verbatim + 36 parameterized tests asserting retention/subjects per stream.                                                                                       |
| 3    | `8671d6c` | #17 | **SAFETY-CRITICAL** | `client.py` async `JetStreamClient` (connect/ensure_streams/publish/subscribe/close/publish_finding) + 3 typed exceptions + 28 mocked tests + nats-py dep.                                                                                   |
| 4    | `c712565` | #18 | **SAFETY-CRITICAL** | `publish()` Q3 resolution: kwarg → contextvar → raise; `Nexus-Correlation-Id` header propagation. 6 new tests covering 4 plan-required paths + ordering safety.                                                                              |
| 5    | `9d23ba1` | #19 | LOW-RISK            | 16 new test functions yielding 19 new cases expanding mocked client coverage (edge cases, parameterized per-stream, post-close lifecycle, determinism).                                                                                      |
| 6    | `f84a22f` | #20 | **SAFETY-CRITICAL** | Live NATS round-trip integration test (`NEXUS_LIVE_NATS=1` gated). 4 tests including the load-bearing publish→real broker→subscribe→header round-trip.                                                                                       |
| 7    | `3725f8d` | #21 | LOW-RISK            | Operator runbook at `docs/runbooks/fabric.md`, 7 sections covering substrate ops, both NATS-up paths (Docker + brew binary), JetStreamClient usage, the 5-streams table, correlation_id contract, deferments, live-lane reproduce-the-proof. |
| 8    | _this PR_ | TBD | LOW-RISK            | This record (closes F.7 v0.1).                                                                                                                                                                                                               |

Three of the seven implementing PRs (#17, #18, #20) were SAFETY-CRITICAL per the plan's "Tasks 3, 4, 6 in particular" flag and carried the verified-against-HEAD sentence in their PR bodies — naming the short hash, full hash, gates-run-AFTER-commit phrasing, and clean `git status --short` claim, written explicitly against the Task-13 antecedent failure mode.

---

## ADR-004 conformance check

The plan's spec for this record (row 8): "every clause of ADR-004 either implemented or explicitly deferred to a named v0.x". Walking ADR-004's substantive points:

| ADR-004 clause                                                                      | Status in F.7 v0.1                                                                                                                                                                                                                                                           |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Adopt NATS JetStream as the platform fabric in both planes                          | **Single-plane v0.1.** Control-plane fabric reachable + exercised. Edge-plane leaf-node ↔ control deferred to **E.1 + E.2 (edge plane track)**.                                                                                                                              |
| Define five named buses with explicit subject conventions, schemas, retention, ACLs | **Subjects + retention implemented** (`streams.py`, `subjects.py` pre-existing); **schemas partial** (OCSF on `findings.>` only — see next row); **ACLs deferred to F.7 v0.x** (subject-scoping is builder-level; broker-level NATS auth tokens are hardening).              |
| OCSF v1.3 as canonical finding wire format on `findings.>`                          | **Implemented.** `publish_finding()` wraps via `NexusEnvelope.wrap()` and JSON-encodes deterministically. Non-findings streams accept arbitrary bytes per Q5.                                                                                                                |
| Protobuf schemas for `events.>` / `commands.>` / `approvals.>` / `audit.>`          | **Deferred to F.7 v0.x.** Per Q5: each stream's first consumer's plan defines the wire format; the streams accept arbitrary bytes today.                                                                                                                                     |
| Outbound-only mTLS leaf-node from edge                                              | **Deferred to E.1 + E.2 (edge plane track).** v0.1 is single-plane substrate.                                                                                                                                                                                                |
| Air-gap = leaf-node disconnected operation                                          | **Deferred to E.1 + E.2 (edge plane track).** Same.                                                                                                                                                                                                                          |
| `correlation_id` on every message (mandatory cross-cutting)                         | **Implemented** as bus property: `publish()` resolves kwarg → contextvar → raise BEFORE network call; resolved value set as `Nexus-Correlation-Id` header on every successful publish. Q3 path-matrix covered in 7 tests (4 plan-required + 2 safety + 1 live).              |
| Per-tenant subject scoping                                                          | **Subject-level scoping implemented** (subject builders in `shared.fabric.subjects` per tenant). **Broker-level ACL enforcement deferred to F.7 v0.x** (hardening).                                                                                                          |
| Hash-chained signed audit log + KMS-signed `audit.>` messages                       | **Stream declared + reachable**; **KMS signing deferred to F.7 v0.x hardening.** Per ADR-004's "KMS-signed for audit" language is forward-looking; v0.1 ensures the stream exists with the right retention; the signing wrapper is a v0.x layer above the stream.            |
| Self-evolution as a normal subscriber on `audit.>`                                  | **Substrate available, consumer deferred.** A.4 Meta-Harness on `audit.>` lands as a separate plan when the consumer is built (see "What F.7 v0.1 unblocks" below).                                                                                                          |
| Replay, retry, dedup, backpressure with one implementation                          | **Defaults inherited from NATS JetStream.** Production-tuning beyond defaults deferred to F.7 v0.x — per ADR-004's "one implementation each instead of N" framing, the substrate ships with defaults; tuning happens when the first consumer's traffic profile motivates it. |
| ClickHouse `findings.>` consumer co-location vs separate service                    | **Decided when the first non-Cloud-Posture findings consumer ships.** Per ADR-004 §"Neutral / unknown" item 2; not blocking v0.1 substrate closure.                                                                                                                          |
| JetStream cluster sizing (3-node R6i.large vs single-node-per-edge)                 | **Deferred to E.x deployment.** Per ADR-004 §"Neutral / unknown" item 1; v0.1 ships single-node dev shape.                                                                                                                                                                   |

Every substantive ADR-004 clause is accounted for: **implemented** (with test evidence), **deferred to a named v0.x** (with the named follow-on plan), or **deferred to a named cross-track plan** (E.1+E.2 for the edge/topology clauses). Nothing is silently dropped.

---

## Coverage delta vs pre-F.7-v0.1 baseline

Cumulative `git diff --stat` from `44ab257` (the F.7 v0.1 plan-PR merge commit, F.7 base) to `ad5e512` (`main` HEAD after Task 7 closes):

| File                                                                                    | Δ LOC                          |
| --------------------------------------------------------------------------------------- | ------------------------------ |
| `packages/shared/src/shared/fabric/client.py` (NEW)                                     | +382                           |
| `packages/shared/src/shared/fabric/streams.py` (NEW)                                    | +121                           |
| `packages/shared/src/shared/fabric/__init__.py` (re-exports)                            | +42 / −1                       |
| `packages/shared/pyproject.toml` (`nats-py>=2.7.0`)                                     | +1                             |
| `uv.lock` (nats-py + transitive deps)                                                   | +11                            |
| `packages/shared/tests/test_fabric_streams.py` (NEW)                                    | +146 / 36 tests                |
| `packages/shared/tests/test_fabric_client.py` (NEW)                                     | +1033 / 53 tests               |
| `packages/shared/tests/integration/__init__.py` (NEW, empty)                            | 0                              |
| `packages/shared/tests/integration/test_fabric_client_live.py` (NEW)                    | +427 / 4 live tests            |
| `docker/docker-compose.dev.yml` (Task 1 hardening)                                      | +26 / −3                       |
| `docs/runbooks/fabric.md` (NEW)                                                         | +235                           |
| `docs/superpowers/plans/2026-05-17-f-7-v0-1-fabric-runtime.md` (status-table hash-pins) | +14 / −6                       |
| **Total**                                                                               | **+2431 inserts, −17 deletes** |

| Test surface                                              | Pre-F.7 baseline | After F.7 v0.1 | Δ                              |
| --------------------------------------------------------- | ---------------- | -------------- | ------------------------------ |
| Repo-wide mocked lane (`pytest -q` passed)                | 2542             | 2631           | **+89**                        |
| Repo-wide skipped (gated lanes; live + ollama + postgres) | 17               | 21             | +4 (the live NATS lane)        |
| F.7 client surface (`test_fabric_client.py`)              | 0                | 53             | +53                            |
| F.7 streams surface (`test_fabric_streams.py`)            | 0                | 36             | +36                            |
| F.7 live lane (`test_fabric_client_live.py`)              | 0                | 4              | +4 (`NEXUS_LIVE_NATS=1`-gated) |

---

## Permanent documented limitation — version deviation (`v2.14.0` vs `nats:2.10-alpine`)

**This is the permanent home for the disclosed-not-silent version note from Task 6 + Task 7's runbook §2b. It must not live only there.**

### What happened

- The F.7 v0.1 docker-compose service in Task 1 pins `nats:2.10-alpine` (the image tag was chosen for the existing service ship-shape and the Alpine variant's small footprint).
- Task 6's live-lane proof ran on `nats-server v2.14.0` — the version Homebrew currently ships. The development environment Task 6 was authored in did not have Docker installed (`docker --version` returned "command not found"); `nats-server` via `brew install nats-server` was the only path to a real broker for the proof.
- I chose to install `nats-server` (brew, `v2.14.0`) and run the live proof against it rather than skip the live test or pretend the mocked round-trip was sufficient.

### What this means for the substrate's correctness claim

- The JetStream protocol surface that `JetStreamClient` exercises (`connect()`, `add_stream`/`stream_info`, `publish` with headers, `subscribe` with durable push consumer, `delete_stream` for cleanup) is **stable across NATS 2.10 / 2.11 / 2.14**. NATS's compatibility policy is explicit about wire-format and JetStream API stability within the 2.x line; only major-version transitions (1.x → 2.x, 2.x → 3.x) are wire-format breaking.
- The `Nexus-Correlation-Id` header round-trip is a NATS-protocol-level feature (NATS supports headers since 2.0); it is not version-gated above 2.10.
- The 5-stream `StreamConfig` shape (subjects / max_age / discard / max_msgs_per_subject / retention=LIMITS / storage=FILE) uses no fields introduced after 2.10.

### What this means for production

- **Production deployments should match the compose image's pin (`nats:2.10-alpine`) or any later 2.x release.** The verified-against shape is JetStream 2.10+; running 2.14.0 in production is functionally equivalent for the surface F.7 v0.1 exercises.
- A future plan that wants to depend on a NATS feature **introduced after 2.10** (e.g., a 2.11+ subject-mapping primitive) must (a) bump the docker-compose image pin, (b) update the runbook §2b version note, and (c) update this record's "Permanent documented limitation" section.
- The deviation does **not** invalidate any of the 4 live-test assertions: header propagation, correlation_id refusal precondition, OCSF envelope wire format, idempotent stream creation. Each of those is a NATS 2.0+ feature.

### Why this is acceptable (not a defect to fix later)

- The disclosure was named in PR #20's body (the load-bearing PR for the substrate proof), in PR #21's runbook §2b, and now permanently here.
- An alternative — running the live proof against the exact image pinned in compose — would have required either (a) installing Docker locally (a tooling-environment decision the user did not authorize when Task 6 needed to ship), or (b) deferring the live proof until CI had a broker (rejected by the user's Task-6 requirements — the live proof was the non-negotiable plan-closer).
- The mocked-lane coverage (53 client tests + 36 stream tests, 89 total) exercises the F.7 client's contract independent of broker version; the live-lane proof exercises the JetStream protocol surface, which is stable across 2.10/2.11/2.14.

### What future tracks should do

- **F.7 v0.2 (D.7 migration)**: re-run the live lane against `nats:2.10-alpine` once the migration test environment has Docker. If the protocol surface used by D.7 introduces anything ≥ 2.11, bump the compose pin AND re-record this section to reflect the new floor.
- **Production hardening**: pin the docker-compose image to a specific 2.10.x patch release for reproducibility; or move to a tag that bundles 2.10.x security patches automatically.
- **CI integration** (if the live lane ever runs in CI): use the docker-compose image directly to eliminate this version-gap permanently.

---

## Carried watch-item closure (mock-now → live-now, closed by execution)

Tasks 3, 4, and 5 each shipped with a carried watch-item explicitly named in their PR bodies:

> _"Task 6 (`NEXUS_LIVE_NATS=1` round-trip against a real broker) is the load-bearing live proof of the substrate. Tasks 3+4+5 are mock-proven only. Same mock-now/live-later shape as A.1 Task 13 where a live proof once merged unverified. Task 6 does not get skipped, absorbed, or quick-merged; it gets full A.1-live-cluster-grade scrutiny and a verified-against-HEAD sentence."_

**This watch-item is closed by execution, not by assertion.** Task 6 (PR #20, commit `f84a22f`) landed with:

- 4 live tests **GREEN** against a real `nats-server v2.14.0` broker (`4 passed in 0.42s`).
- The verified-against-HEAD sentence in the PR body, naming short hash + full hash + gates-run-AFTER-commit phrasing + clean `git status --short`.
- Full A.1-live-cluster-grade scrutiny in the PR review (per the user's review comment on PR #20: "reviewed at full A.1-live-cluster grade and APPROVED. All four requirements met on evidence").
- Live-lane re-run captured against the post-commit HEAD (not editor-only state).

The mocked round-trip in `test_fabric_client.py` is **necessary but not sufficient**; the live round-trip in `test_fabric_client_live.py` is the sufficient condition. Both are in main as of Task 7's merge.

The F.7 v0.1 substrate is no longer a hypothesis. It is empirically demonstrated.

---

## Breaking-change note

**None.** F.7 v0.1 has no prior consumers. The `JetStreamClient` is a new public API; the streams are newly declared; no agent migrated onto the bus in v0.1.

Existing agents continue to work unchanged: filesystem-mediated handoffs (D.6 `findings.json` → A.1 ingest, etc.) are untouched. v0.1 does not read or write the bus from any agent.

The substrate this v0.1 lands on is stable. `shared.fabric.correlation`, `shared.fabric.envelope`, `shared.fabric.subjects` are unchanged in v0.1; v0.1 adds `streams.py` and `client.py` alongside them.

This contract becomes the v0.2 starting point. **F.7 v0.2 (D.7 migration) WILL run ADR-010's eligibility test** — at that point F.7 has a prior version with a public API surface (the `JetStreamClient`), and the eligibility test applies meaningfully.

---

## Process notes — F.7 v0.1 executed under ADR-011

Recording honestly, in source-of-truth form, so future plans inherit the history rather than rediscover it. Same self-documenting-history discipline as A.1 v0.1.1's four-boundary process notes.

### Smooth execution under the discipline ADR-011 established

F.7 v0.1 is the first plan to execute end-to-end under [ADR-011](decisions/ADR-011-pr-flow-and-branch-protection-discipline.md) (accepted at PR #14 close). All 7 task PRs (and this Task-8 PR) operated under all four ADR-011 disciplines from PR-open without exception:

- **Discipline 1 (labelling at PR-open).** Every PR declared its risk label in the first line of the body. 4 LOW-RISK (Tasks 1, 2, 5, 7) and 3 SAFETY-CRITICAL (Tasks 3, 4, 6) per the plan's "Tasks 3, 4, 6 in particular" flag. The reviewer did not override any label (one was specifically reviewed for upgrade-risk and confirmed at LOW-RISK: Task 5's expansion was reviewed against the rule "if any new test changes client behavior, upgrade it yourself"; none did).
- **Discipline 2 (branch protection).** All merges went through the protected path on `main`. `bypass_actors: []` was structurally enforced via `.github/branch-protection.json`. No direct-to-main pushes.
- **Discipline 3 (verified-against-HEAD sentence).** The 3 SAFETY-CRITICAL PRs (#17, #18, #20) each carried the sentence: short hash, full hash, gates-run-AFTER-commit phrasing, clean `git status --short`. Each was written explicitly against the Task-13 antecedent (editor-only fix that never reached the commit) — the exact failure mode this sentence was instituted to prevent.
- **Discipline 4 (report → review → merge, agent does not merge).** All 7 task PRs were reported and then merged by the human reviewer. The agent did not merge any PR. This Task-8 PR follows the same cadence.

### Two disclosed deviations (both named in their respective PR bodies)

1. **Task 6 broker version: `nats-server v2.14.0` vs the compose image's `nats:2.10-alpine`.** Disclosed in PR #20's body, named in Task 7's runbook §2b, and now permanently recorded above under "Permanent documented limitation — version deviation". JetStream protocol stable across these versions; the substrate behaviour proven is the same. The alternative would have been to skip the live proof (rejected by the user's Task-6 requirements) or to install Docker locally (a tooling decision the user did not authorize for that moment).
2. **Task 7 README banner omission.** Plan row 7 said "README banner added to `packages/shared/README.md` (if extant)". The file does not exist; the banner was correctly skipped per the plan's conditional. Disclosed in PR #21's body, in the implementing commit message, and in the plan-status row pin for Task 7.

No other deviations. Specifically: no editor-only fixes that never reached a commit (the Task-13 antecedent), no direct-to-main pushes (the pre-A.1.v0.1.1 antecedent), no live tests merged on assertion without empirical proof (the Task-13/§8-Entry-2 antecedent).

### One small mechanical note (not a process deviation)

Task 4's ruff/format run auto-converted `asyncio.TimeoutError` → builtin `TimeoutError`. The two have been aliases since Python 3.11 (PEP 654); the conversion is a behaviour-preserving lint rule (`UP041`). Noted in the Task 4 implementing commit message for completeness.

---

## Hard scope boundary — preserved exactly

The F.7 v0.1 plan's hard scope boundary, restated verbatim and preserved through every task:

**F.7 v0.1 = bus runtime live. NO retroactive migration of existing agents' filesystem handoffs.**

- **D.7 Investigation migration onto `events.>`** is **F.7 v0.2, a separate plan, not started.**
- **Cloud-Posture / D.5 / D.6 finding handoffs migrating onto `findings.>`** are **F.7 v0.3+, separate plans, not started.**
- **Edge-plane leaf-node ↔ control-plane connection** is **E.1 + E.2 scope, separate plans, not started.**

Zero agents publish or subscribe on the bus today. The substrate is live, exercised by the integration lane, and ready for the first consumer migration to begin under ADR-010's eligibility test framework.

---

## What F.7 v0.1 unblocks (forward references)

After this record closes, the following plans become straightforwardly shippable because their transport substrate is no longer hypothetical:

| Future plan                           | What it builds on F.7 v0.1                                                                                               |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Supervisor / delegation primitive     | Fan-out from one supervisor to N sub-agents routes through `events.>` instead of in-process function calls.              |
| A.4 Meta-Harness                      | Subscribes to `audit.>` + `events.>` for self-evolution trace aggregation instead of reading filesystem snapshots.       |
| D.7 v0.2 cross-incident graph queries | Correlates findings across agents via `findings.>` (the F.7 v0.2 first-consumer migration).                              |
| S.1 Console real-time activity feed   | Subscribes to `events.>` for real-time agent activity instead of polling per-agent filesystem state.                     |
| E.1 edge plane                        | Leaf-nodes into the F.7 control-plane substrate via outbound mTLS; no second transport layer to invent.                  |
| F.6 end-to-end correlation_id         | Already bus-enforced (the publish boundary refuses messages without `correlation_id`) rather than per-agent disciplined. |

None of those happen in v0.1. Each gets its own plan with its own ADR-010 eligibility test.

---

## Immediate next-plan gate

**F.7 v0.2 — D.7 Investigation migration onto `events.>`.**

This is the first within-agent version extension that consumes F.7 v0.1's substrate. Per the plan's compatibility-contract section: F.7 v0.2 onward WILL use ADR-010's eligibility test (since v0.1 establishes a public API surface — the `JetStreamClient` — that v0.2 must preserve under the additive-surface invariant).

The v0.2 plan, when authored, must:

1. Run and record ADR-010's six-condition eligibility test against F.7 v0.1 as the prior version.
2. Migrate D.7 from filesystem-mediated handoffs onto `events.>` as its single consumer surface.
3. Re-run the `NEXUS_LIVE_NATS=1` lane to prove the migration end-to-end against a real broker — same load-bearing live-proof discipline that closed v0.1's substrate.
4. Address any NATS-version dependency that exceeds 2.10 by updating the compose pin AND this record's "Permanent documented limitation" section.

Other v0.2/v0.3 candidates (Cloud-Posture / D.5 / D.6 migrations onto `findings.>`) are deferred to v0.3+ per the plan's compatibility contract; each gets its own plan and its own ADR-010 eligibility test.

---

## Sign-off

F.7 v0.1 closes with the substrate empirically demonstrated against a real NATS broker. The 4 live tests prove the publish → real broker → subscribe round-trip with `Nexus-Correlation-Id` header propagation. The 89 mocked tests prove the contract per-method. The hard scope boundary is preserved exactly: zero agents migrated; D.7 is v0.2; Cloud-Posture/D.5/D.6 are v0.3+.

The version deviation (`v2.14.0` vs `nats:2.10-alpine`) is permanently documented above as a disclosed-not-silent limitation. The carried watch-item from Tasks 3/4/5 is closed by Task 6's execution, not by assertion. The README-banner omission is disclosed per the plan's "if extant" conditional. No other deviations.

The directional re-read that selected F.7 as the next plan (platform-line criterion, not coverage-line) was correct: F.7 v0.1's role is to make the subsequent plans (supervisor primitive, A.4, D.7 v0.2, S.1, E.1) shorter and stronger by putting the transport substrate underneath them. After this record closes, those plans can proceed.

— recorded 2026-05-17 (F.7 v0.1, fabric-runtime plan close)
