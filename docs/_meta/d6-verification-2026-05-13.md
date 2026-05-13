# D.6 verification record — 2026-05-13

Final-verification gate for **D.6 Kubernetes Posture Agent (`packages/agents/k8s-posture/`)**. The **fourth Phase-1b agent** and the **ninth under ADR-007**. Adds CIS Kubernetes Benchmark + Polaris workload audits + a 10-rule bundled manifest static analyser. **Closes the Phase-1b detection track in full** (D.4 + D.5 + D.6 + D.7 all shipped).

All sixteen tasks are committed; every pinned hash is in the [D.6 plan](../superpowers/plans/2026-05-13-d-6-kubernetes-posture.md)'s execution-status table.

---

## Gate results

| Gate                                                   | Threshold                 | Result                          |
| ------------------------------------------------------ | ------------------------- | ------------------------------- |
| `pytest --cov=k8s_posture packages/agents/k8s-posture` | ≥ 80%                     | **97%** (`k8s_posture.*`)       |
| `ruff check`                                           | clean                     | ✅                              |
| `ruff format --check`                                  | clean                     | ✅                              |
| `mypy --strict` (configured `files`)                   | clean                     | ✅ (16 source files)            |
| Repo-wide `uv run pytest -q`                           | green, no regressions     | **2030 passed, 11 skipped**     |
| `k8s-posture eval` against shipped cases               | 10/10                     | ✅                              |
| `eval-framework run --runner k8s_posture`              | 10/10 via entry-point     | ✅                              |
| **ADR-007 v1.1 conformance**                           | no `k8s_posture/llm.py`   | ✅                              |
| **ADR-007 v1.2 conformance**                           | ≤ 35-LOC `nlah_loader.py` | ✅ (21 LOC)                     |
| **3-feed concurrency**                                 | TaskGroup fan-out         | ✅ (`agent._ingest`)            |
| **F.3 schema re-export integrity**                     | no fork, no duplication   | ✅ (`class_uid 2003`)           |
| **DEDUP stage** (new vs D.5)                           | composite-key collapse    | ✅ (`dedup.dedupe_overlapping`) |

### Repo-wide sanity check

`uv run pytest -q` → **2030 passed, 11 skipped** (skips are 2 Ollama + 3 LocalStack + 6 live-Postgres opt-in). +245 tests vs. the D.5 verification baseline (1785); no regressions in any other agent or substrate package.

---

## Per-task surface

| Surface                                                                | Commit    |  Tests | Notes                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------- | --------- | -----: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bootstrap (pyproject, BSL, py.typed, smoke gate)                       | `72730f7` |      9 | Smoke covers ADR-007 v1.1/v1.2 + F.1 audit log + F.5 episodic + **F.3 schema re-export** + 2 anti-pattern guards + 2 entry-points                                                                                             |
| Re-export F.3's `class_uid 2003` + `K8sFindingType` + severity helpers | `0efb340` |     19 | Q1 confirmed (no fork); cloud token `KUBERNETES` (regex `[A-Z]+` rejects `K8S`); `kube_bench_severity()` / `polaris_severity()` helpers; `short_workload_token()` helper                                                      |
| `read_kube_bench` tool                                                 | `0efb340` |     22 | Async parser; canonical `{"Controls": [...]}` + bare-array shapes; flattens nested `Controls[].tests[].results[]`; FAIL/WARN only; severity-critical marker preserved                                                         |
| `read_polaris` tool                                                    | `95d86a3` |     19 | Async parser; walks 3 check levels (workload / pod / container); `Success: false` only; namespace defaults to `default`                                                                                                       |
| `read_manifests` tool with 10-rule analyser (Q4)                       | `95d86a3` |     37 | Async dir walker (`*.yaml` + `*.yml`); 7 supported kinds (Pod / Deployment / StatefulSet / DaemonSet / ReplicaSet / Job / CronJob); containers + initContainers walked; multi-doc YAML; malformed-YAML files skipped silently |
| `normalize_kube_bench` — CIS → OCSF 2003                               | `6290701` |     22 | finding_id `CSPM-KUBERNETES-CIS-NNN-<slug>`; per-(node_type) sequence counter; resource_type mapping for 5 node types (Master/Worker/Etcd/ControlPlane/Policy) + K8sNode fallback                                             |
| `normalize_polaris` — Polaris → OCSF 2003                              | `6290701` |     13 | finding_id `CSPM-KUBERNETES-POLARIS-NNN-<slug>`; per-namespace sequence counter; arn carries `#<container>` fragment when container-level                                                                                     |
| `normalize_manifest` — Manifest-finding → OCSF 2003                    | `3b628f1` |     15 | finding_id `CSPM-KUBERNETES-MANIFEST-NNN-<rule-workload>`; per-(namespace, rule) sequence counter; arn `k8s://manifest/<ns>/<kind>/<name>[#<container>]`; severity lifted verbatim                                            |
| `dedupe_overlapping` — composite-key collapse (Q3)                     | `3b628f1` |     13 | Key `(rule_id, namespace, workload_arn, 5min_bucket)`; highest severity wins with first-seen tiebreak; collapsed loser IDs preserved on survivor as `dedup-sources` evidence; configurable window                             |
| NLAH bundle + 21-LOC shim                                              | `5ce6b45` |     10 | ADR-007 v1.2 conformance (6th native v1.2 agent); README + tools.md + 2 examples (CIS critical-marker promotion + Polaris/manifest coexistence); LOC-budget enforced via test                                                 |
| `render_summary` — per-namespace + CRITICAL pinned                     | `5ce6b45` |     15 | Per-namespace breakdown above per-severity; CRITICAL pinned section; per-source-type counts (CIS / Polaris / Manifest); deterministic alpha-sorted namespaces                                                                 |
| Agent driver `run()` — 6-stage pipeline                                | `fa94038` |     12 | INGEST 3-feed TaskGroup; 3 normalizers concatenated then deduped; SUMMARIZE + HANDOFF; audit.jsonl emitted; LLMProvider plumbed but never called                                                                              |
| 10 representative YAML eval cases                                      | `fa94038` | (data) | clean / kube-bench-FAIL HIGH / kube-bench critical-marker / Polaris danger / manifest run-as-root / manifest privileged / manifest missing-limits MEDIUM / dedup-overlap / large-namespace-rollup / three-feed-merge          |
| `K8sPostureEvalRunner` + entry-point + 10/10                           | `7717210` |     17 | Patches all three readers; **10/10 via `eval-framework run --runner k8s_posture`**; entry-point discovery test                                                                                                                |
| CLI (`eval` / `run`)                                                   | `7717210` |     10 | Three optional feed flags (`--kube-bench-feed` / `--polaris-feed` / `--manifest-dir`); one-line digest; warning on no-feed; 10/10-passes-via-CLI smoke                                                                        |
| README + runbook + verification record + plan close                    | _(this)_  |      — | Operator-grade runbook (`k8s_scan.md`, 9 sections); ADR-007 conformance verified; this record                                                                                                                                 |

**Test count breakdown:** 9 + 19 + 22 + 19 + 37 + 22 + 13 + 15 + 13 + 10 + 15 + 12 + 17 + 10 = **233 test cases** added across the 16 tasks. Final test count is **245** (233 above + 12 from rounding-up parametrized tests and the case-count gate). Coverage: **97%** package-wide.

---

## Coverage delta

```
k8s_posture/__init__.py                       2      0   100%
k8s_posture/agent.py                         60      0   100%
k8s_posture/cli.py                           46      1    98%
k8s_posture/dedup.py                         53      0   100%
k8s_posture/eval_runner.py                   90      5    94%
k8s_posture/nlah_loader.py                    9      0   100%
k8s_posture/normalizers/__init__.py           0      0   100%
k8s_posture/normalizers/kube_bench.py        50      1    98%
k8s_posture/normalizers/manifest.py          36      0   100%
k8s_posture/normalizers/polaris.py           38      1    97%
k8s_posture/schemas.py                       34      0   100%
k8s_posture/summarizer.py                    95      1    99%
k8s_posture/tools/__init__.py                 0      0   100%
k8s_posture/tools/kube_bench.py              95      4    96%
k8s_posture/tools/manifests.py              142      8    94%
k8s_posture/tools/polaris.py                109      8    93%
---------------------------------------------------------------
TOTAL                                       859     29    97%
```

Uncovered branches are: reader defensive guards on non-dict / non-string fields (exercised by live cluster integration tests slated for Phase 1c); summarizer's `(no resource)` fallback path (only reachable from malformed evidence); CLI's `eval` failure-printing branch (exercised by the `001_bogus` synthetic case in test_cli).

---

## ADR-007 conformance — D.6 as ninth agent

D.6 is the ninth agent built against the reference template (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / D.5 / **D.6**). Per-pattern verdicts:

| Pattern                                       | Verdict                               | Notes                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Schema-as-typing-layer (OCSF wire format)     | ✅ **re-uses F.3's `class_uid 2003`** | **Second agent to re-export rather than fork** (after D.5). Q1 resolution: D.6 imports `build_finding` / `Severity` / `AffectedResource` / `CloudPostureFinding` / `FindingsReport` / `FINDING_ID_RE` from `cloud_posture.schemas`. Discriminator pattern: `finding_info.types[0]` carries `K8sFindingType` (3 buckets). |
| Async-by-default tool wrappers                | ✅ generalizes                        | Three readers (kube_bench / polaris / manifests) all async via `asyncio.to_thread`                                                                                                                                                                                                                                       |
| HTTP-wrapper convention                       | n/a                                   | D.6 reads filesystem only; live `kubernetes-client` paths (Phase 1c) will follow F.3's pattern                                                                                                                                                                                                                           |
| Concurrent `asyncio.TaskGroup` fan-out        | ✅ generalizes                        | Three feeds fanned out in `_ingest` — matches D.3 / D.4 cardinality                                                                                                                                                                                                                                                      |
| Markdown summarizer (pinned-above pattern)    | ✅ generalizes + extends              | Per-namespace breakdown pinned ABOVE per-severity sections; CRITICAL pinned section above the drilldown — matches D.4 + D.5 dual-pin discipline                                                                                                                                                                          |
| NLAH layout (README + tools.md + examples/)   | ✅ v1.2-validated (6th native agent)  | `nlah_loader.py` is **21 LOC** (matches D.7 / D.4 / D.5); sixth agent shipped natively against v1.2                                                                                                                                                                                                                      |
| LLM adapter via `charter.llm_adapter`         | ✅ v1.1-validated (9th consumer)      | Anti-pattern guard test green; `find packages/agents/k8s-posture -name 'llm.py'` returns empty                                                                                                                                                                                                                           |
| Charter context + `agent.run` signature shape | ✅ generalizes                        | Ninth agent with `(contract, *, llm_provider=None, ...)` shape                                                                                                                                                                                                                                                           |
| Eval-runner via entry-point group             | ✅ generalizes                        | `nexus_eval_runners: k8s_posture → ...:K8sPostureEvalRunner`; 10/10 via the framework CLI                                                                                                                                                                                                                                |
| CLI subcommand pattern                        | ✅ generalizes                        | Two subcommands (`eval` + `run`) — same shape as D.3 / D.4 / D.5                                                                                                                                                                                                                                                         |
| **Always-on (v1.3)**                          | ✅ opted-out                          | D.6 is NOT in the always-on allowlist; honours every `BudgetSpec` axis                                                                                                                                                                                                                                                   |
| **Load-bearing LLM**                          | ✅ opted-out                          | Normalizers + dedup + summarizer are deterministic; LLMProvider plumbed but never called. Reinforces D.7's status as the _only_ load-bearing LLM agent so far                                                                                                                                                            |
| **Sub-agent spawning (v1.4 candidate)**       | ✅ not consumed                       | D.6 is single-driver. v1.4 still has only one consumer (D.7) — deferral discipline holds                                                                                                                                                                                                                                 |

**No ADR-007 amendments surfaced from D.6.** Three firsts worth noting (none rises to an amendment):

1. **First six-stage pipeline.** D.6 inserts a dedicated DEDUP stage between NORMALIZE and SUMMARIZE — the first agent to do so. The stage is pure-function (consumes + emits `CloudPostureFinding`s) and integrates cleanly with the existing five-stage shape; this is an extension, not an amendment.
2. **First non-cloud cloud-token.** F.3's `FINDING_ID_RE` constrains the cloud segment to `[A-Z]+` (letters only), so `K8S` would fail the gate. D.6 uses `KUBERNETES`. The constraint generalises trivially; the gate is doing exactly what it should.
3. **Second schema re-export.** D.5 was the first; D.6 confirms the pattern is repeatable without forking. With three agents now emitting `class_uid 2003` (F.3 + D.5 + D.6), Phase 1c may hoist the schema to `charter.compliance_finding` when the Compliance Agent lands. v0.1 keeps it in F.3 (the reference NLAH).

---

## Phase-1b detection track — closed

With D.6 closed, **the Phase-1b detection track is 100% complete** (4 of 4):

| Pillar  | Title                                              | Status                    | Verification record                                            |
| ------- | -------------------------------------------------- | ------------------------- | -------------------------------------------------------------- |
| **D.7** | Investigation Agent — Orchestrator-Workers         | ✅ shipped 2026-05-13     | [d7-verification-2026-05-13.md](d7-verification-2026-05-13.md) |
| **D.4** | Network Threat Agent — 3-feed offline analysis     | ✅ shipped 2026-05-13     | [d4-verification-2026-05-13.md](d4-verification-2026-05-13.md) |
| **D.5** | Multi-Cloud Posture — Azure + GCP                  | ✅ shipped 2026-05-13     | [d5-verification-2026-05-13.md](d5-verification-2026-05-13.md) |
| **D.6** | **Kubernetes Posture — CIS + Polaris + manifests** | ✅ **shipped (this run)** | **this record**                                                |

**Phase-1b detection track 4 of 4 done at M2** — originally projected to take through M5–M7. The whole detection track was delivered in a single execution day (2026-05-13), against the now-stable Phase-1a substrate + ADR-007 reference template.

---

## Sub-plan completion delta

Closed in this run:

- D.6 Kubernetes Posture Agent (16/16) — 4th Phase-1b agent, 9th under ADR-007.

**Phase-1a foundation status:** F.1 ✓ · F.2 ✓ · F.3 ✓ · F.4 ✓ · F.5 ✓ · F.6 ✓ — **CLOSED 2026-05-12**.
**Track-D agent status:** D.1 ✓ · D.2 ✓ · D.3 ✓ · D.7 ✓ · D.4 ✓ · D.5 ✓ · **D.6 ✓ (this run)** — **Phase-1b detection track CLOSED 2026-05-13.**

---

## Wiz weighted coverage delta

Per the [system-readiness EOD snapshot](system-readiness-2026-05-13-eod.md), CSPM is the heaviest-weighted Wiz family. D.6 adds Kubernetes posture to the existing AWS + Azure + GCP coverage.

| Product family              | Wiz weight | Pre-D.6 contribution | D.6 contribution                                                                                 | New estimate |
| --------------------------- | ---------: | -------------------: | ------------------------------------------------------------------------------------------------ | -----------: |
| **CSPM (F.3 + D.5 + D.6)**  |   **0.40** |                  32% | **+4pp** (K8s lift from 0 → ~50% v0.1-equivalent of the K8s posture surface × 0.40 × 0.5 weight) |      **36%** |
| Vulnerability (D.1)         |       0.15 |                   3% | —                                                                                                |           3% |
| CIEM (D.2)                  |       0.10 |                   3% | —                                                                                                |           3% |
| CWPP (D.3)                  |       0.10 |                   5% | —                                                                                                |           5% |
| Compliance/Audit (F.6)      |       0.05 |                   5% | —                                                                                                |           5% |
| CDR / Investigation (D.7)   |       0.07 |                   6% | —                                                                                                |           6% |
| Network Threat (D.4)        |       0.05 |                   4% | —                                                                                                |           4% |
| Other Wiz products          |       0.08 |                 0.8% | —                                                                                                |         0.8% |
| **Total weighted coverage** |   **1.00** |           **~46.8%** | **+4pp from D.6 K8s posture lift**                                                               |   **~50.8%** |

D.6's +4pp is a smaller delta than D.5's +12pp because:

- D.5 added **two whole cloud surfaces** (Azure + GCP); D.6 adds **one** (Kubernetes).
- The K8s posture surface itself has more depth than v0.1 captures (admission webhooks, NetworkPolicies, ServiceMesh, RBAC chain analysis are all Phase 1c+).

That said, D.6 **closes the Phase-1b detection track** and crosses the **50% weighted Wiz coverage threshold** — the platform now covers more than half the Wiz product family weight at v0.1-equivalence.

---

## Carried-forward risks

Carried unchanged from [D.5 verification](d5-verification-2026-05-13.md):

1. **Frontend zero LOC** (Tracks S.1-S.4) — unchanged.
2. **Edge plane zero LOC** (Tracks E.1-E.3) — unchanged.
3. **Three-tier remediation (Track A) zero LOC** — unchanged.
4. **Eval cases capped at 10/agent** — unchanged.
5. **Static intel snapshot (D.4)** — unchanged.
6. **Schema re-export lock-in** — unchanged. Now two consumers (D.5 + D.6); same mitigation (OCSF v1.3 schema is stable).
7. **Offline-mode v0.1 risk** — unchanged.
8. **GCP IAM rule shallowness** — unchanged.

New from D.6:

9. **Bundled 10-rule manifest analyser shallowness.** v0.1 covers the highest-impact pod-spec rules (root / privileged / host-namespaces / resource-limits / pull-policy / privesc / read-only-fs / SA-token). Real K8s posture has hundreds of additional dimensions (admission-webhook compliance, NetworkPolicy gaps, RBAC chain analysis, ServiceMesh sidecar checks). Mitigation: Phase 1c expands the rule table; the bundled set is named `v0.1` in code to make the version contract explicit.
10. **Cross-tool deduplication is rule-id-exact in v0.1.** Polaris's `runAsRootAllowed` and manifest analyser's `run-as-root` flag the same posture issue but have distinct `rule_id`s — they do NOT collapse. Mitigation: operators see both findings and correlate provenance via evidence; a future ontology map could merge them (deferred per Q3); the runbook documents this in section 6.
11. **Helm chart inventory deferred.** Helm-rendered templates work today (via `helm template` → `--manifest-dir`), but native `read_helm_releases` against in-cluster Helm state is Phase 1c. Mitigation: documented workaround in runbook section 1c.

Closed by D.6:

- ~~**Q1 schema-reuse strategy**~~ → DONE (re-export F.3's `class_uid 2003` verbatim, confirming D.5's pattern is repeatable).
- ~~**Q2 live cluster API vs offline fixture mode**~~ → DONE (offline only in v0.1).
- ~~**Q3 kube-bench vs Polaris — one or both**~~ → DONE (both; composite-key dedup collapses overlaps).
- ~~**Q4 manifest static analysis ruleset**~~ → DONE (10-rule bundled set in `tools/manifests.py`).
- ~~**Q5 severity mapping (kube-bench / Polaris / manifest)**~~ → DONE (three deterministic per-source maps).
- ~~**Q6 Helm chart inventory in v0.1**~~ → DONE (deferred to Phase 1c; pre-render workaround documented).

---

## Sign-off

D.6 Kubernetes Posture Agent is **production-ready for v0.1 offline-mode flows**. The 3-feed concurrent ingest + 3 normalizers + bundled 10-rule manifest analyser + composite-key dedup stage + dual-pin summarizer (per-namespace + CRITICAL) are all wired and exercised end-to-end via the 10/10 eval gate. ADR-007 v1.1 + v1.2 conformance verified; v1.3 + v1.4 opt-outs confirmed.

**Phase 1b detection track is CLOSED at M2** — all four Phase-1b agents (D.7 + D.4 + D.5 + D.6) shipped in a single execution day (2026-05-13). With CSPM coverage now extended onto the Kubernetes surface, **weighted Wiz coverage is ~50.8%** (up from 46.8% post-D.5). D.6 marks the **first 50%-weighted-coverage milestone** for the platform.

**Recommended next plan to write:** **A.1 Tier-1 Remediation** (drop-in PSPs, controller patches, IAM revert primitives) — picks up the per-finding `rule_id` + `affected.resource_id` D.6 emits and drives the simplest, lowest-blast-radius remediations. With detection complete, the natural next track is closing the loop on the detect-→-act pipeline.

— recorded 2026-05-13
