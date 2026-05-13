# D.4 verification record — 2026-05-13

Final-verification gate for **D.4 Network Threat Agent (`packages/agents/network-threat/`)**. Agent #6 per the [agent spec](../agents/agent_specification_with_harness.md#agent-6--network-threat-agent); the **second Phase-1b agent** and the **seventh under ADR-007**. Mirrors D.3's three-feed pattern, applied to the network domain instead of the workload domain.

All sixteen tasks are committed; every pinned hash is in the [D.4 plan](../superpowers/plans/2026-05-13-d-4-network-threat-agent.md)'s execution-status table.

---

## Gate results

| Gate                                                         | Threshold                  | Result                       |
| ------------------------------------------------------------ | -------------------------- | ---------------------------- |
| `pytest --cov=network_threat packages/agents/network-threat` | ≥ 80%                      | **94%** (`network_threat.*`) |
| `ruff check`                                                 | clean                      | ✅                           |
| `ruff format --check`                                        | clean                      | ✅                           |
| `mypy --strict` (configured `files`)                         | clean                      | ✅ (17 source files)         |
| Repo-wide `uv run pytest -q`                                 | green, no regressions      | **1571 passed, 11 skipped**  |
| `network-threat eval` against shipped cases                  | 10/10                      | ✅                           |
| `eval-framework run --runner network_threat`                 | 10/10 via entry-point      | ✅                           |
| **ADR-007 v1.1 conformance**                                 | no `network_threat/llm.py` | ✅                           |
| **ADR-007 v1.2 conformance**                                 | ≤ 35-LOC `nlah_loader.py`  | ✅ (21 LOC)                  |
| **3-feed concurrency**                                       | TaskGroup fan-out          | ✅ (`agent._ingest`)         |
| **Deterministic detectors**                                  | no LLM in detection path   | ✅ (all detectors pure)      |

### Repo-wide sanity check

`uv run pytest -q` → **1571 passed, 11 skipped** (skips are 2 Ollama + 3 LocalStack + 6 live-Postgres opt-in). +231 tests vs. the D.7 verification baseline; no regressions in any other agent or substrate package.

---

## Per-task surface

| Surface                                                       | Commit    |  Tests | Notes                                                                                                                           |
| ------------------------------------------------------------- | --------- | -----: | ------------------------------------------------------------------------------------------------------------------------------- |
| Bootstrap (pyproject, BSL, py.typed, README stub, smoke gate) | `ed62347` |      9 | Smoke covers ADR-007 v1.1/v1.2 hoists + F.1 audit log + F.5 episodic + 2 anti-pattern guards + 2 entry-point checks             |
| OCSF schemas — 6 pydantic models                              | `4d67586` |     45 | `2004 + types[0]="network_threat"` (Q1); 4-bucket FindingType; `Detection.dedup_key()` (Q6); `AffectedNetwork`; `build_finding` |
| `read_suricata_alerts` tool                                   | `c7ad964` |     10 | ndjson; alert event_type only; handles Z + `+0000` ISO-8601; forgiving on malformed JSON / missing alert blob                   |
| `read_vpc_flow_logs` tool                                     | `c7ad964` |     10 | v2/v3/v4/v5 superset; gzip + plaintext (magic-bytes); header-driven field map; `-` → 0 for numerics; unmapped extras            |
| `read_dns_logs` tool                                          | `34312bb` |     14 | Multi-format dispatch (first-line peek); BIND regex with `%f`; Route 53 ndjson; qname lowercased + trailing-dot stripped        |
| `detect_port_scan` — connection-rate heuristic                | `34312bb` |     21 | Sliding-window per src; defaults 50/60s; severity 50→200; loopback/link-local filtered; per-src seq numbering                   |
| `detect_beacon` — periodicity analysis                        | `ee4fb54` |     22 | Per (src,dst,port) group; min_count=5, max_cov=0.30, min_period=1.0s (Q3); severity by count + CoV; confidence ∈ [0,1]          |
| `detect_dga` — entropy + bigram heuristic                     | `ee4fb54` |     25 | Per Q2 (no ML in v0.1); second-level label only; Norvig top-50 bigrams; suffix allowlist; dedup by (src,qname)                  |
| `enrich_with_intel` + bundled `data/intel_static.json`        | `7acf6a5` |     17 | CISA KEV + abuse.ch + MITRE refs snapshot; 16 known-bad domains + 12 known-bad CIDRs + 10 Tor CIDRs; severity uplift capped     |
| NLAH bundle + 21-LOC shim                                     | `7acf6a5` |     10 | ADR-007 v1.2 conformance (4th native v1.2 agent); README + tools.md + 2 examples (beacon + DGA); LOC-budget enforced via test   |
| `render_summary` — pinned beacons/DGA above per-section       | `75e0906` |     15 | Mirrors F.6 tamper-pin + D.3 critical-pin; pin order beacons → DGA → per-severity (Critical → Info)                             |
| Agent driver `run()` — 6-stage pipeline                       | `75e0906` |     27 | INGEST 3-feed TaskGroup; PATTERN_DETECT + Suricata lift; ENRICH + uplift; dedup via `Detection.dedup_key()`; HANDOFF artifacts  |
| 10 representative YAML eval cases                             | `7050a1b` | (data) | clean / port_scan / beacon ±variance / dga ±entropy / Suricata / intel uplift / three-feed merge / allowlist suppression        |
| `NetworkThreatEvalRunner` + entry-point + 10/10               | `7050a1b` |     16 | Patches the three readers; **10/10 via `eval-framework run --runner network_threat`**                                           |
| CLI (`eval` / `run`)                                          | _(this)_  |      9 | Three optional feed flags; one-line digest with severity + finding-type breakdown; warning when no feed provided                |
| README + runbook + verification record + plan close           | _(this)_  |      — | Operator-grade runbook (`network_triage.md`, 8 sections); ADR-007 conformance verified; this record                             |

**Test count breakdown:** 9 + 45 + 10 + 10 + 14 + 21 + 22 + 25 + 17 + 10 + 15 + 27 + 16 + 9 = **250 test cases** added by D.4 (10 YAML cases counted under their runner's tests).

---

## Coverage delta

```
network_threat/__init__.py                       2      0   100%
network_threat/agent.py                        104      4    96%
network_threat/cli.py                           49      1    98%
network_threat/data/__init__.py                  0      0   100%
network_threat/detectors/__init__.py             0      0   100%
network_threat/detectors/beacon.py              80      6    92%
network_threat/detectors/dga.py                 73      6    92%
network_threat/detectors/port_scan.py           67      1    99%
network_threat/enrichment.py                   115      6    95%
network_threat/eval_runner.py                  138      6    96%
network_threat/nlah_loader.py                    9      0   100%
network_threat/schemas.py                      225      6    97%
network_threat/summarizer.py                    59      0   100%
network_threat/tools/__init__.py                 0      0   100%
network_threat/tools/dns_log_reader.py         120     18    85%
network_threat/tools/suricata_reader.py         75      7    91%
network_threat/tools/vpc_flow_reader.py         78      6    92%
-------------------------------------------------------------------
TOTAL                                         1194     67    94%
```

Uncovered branches: dns_log_reader's defensive non-string-`answers` fallback + a few BIND-line edge cases not in the 10 shipped fixtures; reader defensive guards on non-file paths (exercised by the live integration tests slated for Phase 1c); enrichment's `ipaddress.ip_address` ValueError fallback on intentionally-bad fixtures.

---

## ADR-007 conformance — D.4 as seventh agent

D.4 is the seventh agent built against the reference template (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / **D.4**). Per-pattern verdicts:

| Pattern                                       | Verdict                                    | Notes                                                                                                                                                         |
| --------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema-as-typing-layer (OCSF wire format)     | ✅ generalizes (same class_uid as D.2/D.3) | Third 2004-class agent: `2004 + types[0]="network_threat"`. Q1 confirmed at Task 2; raw `4001 Network Activity` deferred to the parsed-observation layer only |
| Async-by-default tool wrappers                | ✅ generalizes                             | Three readers (`read_suricata_alerts` / `read_vpc_flow_logs` / `read_dns_logs`) all async via `asyncio.to_thread`                                             |
| HTTP-wrapper convention                       | n/a                                        | D.4 reads filesystem only; no HTTP                                                                                                                            |
| Concurrent `asyncio.TaskGroup` fan-out        | ✅ generalizes                             | Three feeds fanned out in `_ingest`; same shape as D.3's three sensors                                                                                        |
| Markdown summarizer (pinned-above pattern)    | ✅ generalizes + extends                   | **Two** pinned sections (beacons + DGA) above per-severity — D.3 pinned 1 (critical-runtime), F.6 pinned 1 (tamper). First agent to pin two                   |
| NLAH layout (README + tools.md + examples/)   | ✅ v1.2-validated (4th native agent)       | `nlah_loader.py` is **21 LOC** (matches D.7); fourth agent shipped natively against v1.2 (D.3 + F.6 + D.7 + D.4)                                              |
| LLM adapter via `charter.llm_adapter`         | ✅ v1.1-validated (7th consumer)           | Anti-pattern guard test green; `find packages/agents/network-threat -name 'llm.py'` returns empty                                                             |
| Charter context + `agent.run` signature shape | ✅ generalizes                             | Seventh agent with `(contract, *, llm_provider=None, ...)` shape                                                                                              |
| Eval-runner via entry-point group             | ✅ generalizes                             | `nexus_eval_runners: network_threat → network_threat.eval_runner:NetworkThreatEvalRunner`; 10/10 via the framework CLI                                        |
| CLI subcommand pattern                        | ✅ generalizes                             | Two subcommands (`eval` + `run`) — same shape as D.3                                                                                                          |
| **Always-on (v1.3)**                          | ✅ opted-out                               | D.4 is NOT in the always-on allowlist; honours every `BudgetSpec` axis                                                                                        |
| **Load-bearing LLM (v0.1 surface)**           | ✅ opted-out                               | Detectors are deterministic; LLMProvider plumbed but never called. Reinforces D.7's status as the _only_ load-bearing LLM agent so far                        |
| **Sub-agent spawning (v1.4 candidate)**       | ✅ not consumed                            | D.4 is single-driver; doesn't reach for the orchestrator primitive. v1.4 still has only one consumer (D.7) — deferral discipline holds                        |

**No ADR-007 amendments surfaced from D.4.** The first deviation evaluated was the dual-pin pattern in the summarizer (D.3 / F.6 each pin one section; D.4 pins two). This is not amendment-worthy — the pin discipline generalises by data shape, not count.

---

## Phase-1b detection track progress

With D.4 closed, **Phase-1b detection track is half-done**:

| Pillar  | Title                                              | Status                    | Verification record                                            |
| ------- | -------------------------------------------------- | ------------------------- | -------------------------------------------------------------- |
| **D.7** | Investigation Agent — Orchestrator-Workers         | ✅ shipped 2026-05-13     | [d7-verification-2026-05-13.md](d7-verification-2026-05-13.md) |
| **D.4** | **Network Threat Agent — 3-feed offline analysis** | ✅ **shipped (this run)** | **this record**                                                |
| D.5     | CSPM extension #1 (Azure + GCP multi-cloud)        | ⬜ queued                 | —                                                              |
| D.6     | CSPM extension #2 (Kubernetes posture)             | ⬜ queued                 | —                                                              |

**Phase-1b half-done at M2.** Originally projected through M5-M7; running ~10 weeks ahead of schedule. The remaining Phase-1b work (D.5 multi-cloud + D.6 K8s) is pure pattern application — no new architectural decisions blocking.

---

## Sub-plan completion delta

Closed in this run:

- D.4 Network Threat Agent (16/16) — 2nd Phase-1b agent, 7th under ADR-007.

**Phase-1a foundation status:** F.1 ✓ · F.2 ✓ · F.3 ✓ · F.4 ✓ · F.5 ✓ · F.6 ✓ — **CLOSED 2026-05-12**.
**Track-D agent status:** D.1 ✓ · D.2 ✓ · D.3 ✓ · D.7 ✓ · **D.4 ✓ (this run)** · D.5–D.6 pending.

---

## Wiz weighted coverage delta

Per the [system-readiness recommendation](system-readiness-2026-05-13.md), the **Network** Wiz family carries weight ~0.05.

| Product family              | Wiz weight | Pre-D.4 contribution | D.4 contribution       | New estimate |
| --------------------------- | ---------: | -------------------: | ---------------------- | -----------: |
| CSPM (F.3)                  |       0.40 |                   8% | —                      |           8% |
| Vulnerability (D.1)         |       0.15 |                   3% | —                      |           3% |
| CIEM (D.2)                  |       0.10 |                   3% | —                      |           3% |
| CWPP (D.3)                  |       0.10 |                   5% | —                      |           5% |
| Compliance/Audit (F.6)      |       0.05 |                   5% | —                      |           5% |
| CDR / Investigation (D.7)   |       0.07 |                   6% | —                      |           6% |
| **Network Threat (D.4)**    |   **0.05** |                  0pp | **+4pp** (~80% × 0.05) |       **4%** |
| Other Wiz products          |       0.08 |                 0.8% | —                      |         0.8% |
| **Total weighted coverage** |   **1.00** |           **~30.8%** | **+4pp from D.4**      |   **~34.8%** |

D.4's +4pp lands at ~80% of the Network family (the remaining ~20pp comes from Tier-1 `block_ip_at_waf` action which is Phase 1c, ML DGA model also Phase 1c, and cross-window TimescaleDB beacon baselines).

---

## Carried-forward risks

Carried unchanged from [D.7 verification](d7-verification-2026-05-13.md):

1. **Frontend zero LOC** (Tracks S.1-S.4) — unchanged.
2. **Edge plane zero LOC** (Tracks E.1-E.3) — unchanged.
3. **Three-tier remediation (Track A) zero LOC** — unchanged.
4. **Eval cases capped at 10/agent** — unchanged; parallelizable.

New from D.4:

5. **Static intel snapshot.** `data/intel_static.json` is a 2026-05-13 snapshot; CISA KEV + abuse.ch + Tor exit ranges all rotate weekly. D.8 Threat Intel Agent (Phase 1c) integrates live feeds; until then, the operator must refresh the bundled snapshot.
6. **Single-window beacon detection.** v0.1 misses beacons whose period exceeds the input flow-log time range. Phase 1c TimescaleDB integration adds historical baselines.
7. **DGA false-positive ceiling.** The entropy + bigram heuristic occasionally false-positives on consonant-heavy legitimate names (e.g. `stackoverflow.com`). Phase 1c ML model lifts this.

Closed by D.4:

- ~~**Q1 OCSF class verification**~~ → DONE (confirmed 2004 at Task 2; OCSF 4001 stays internal to parsed-observation layer).
- ~~**Q2 DGA approach**~~ → DONE (entropy + n-gram heuristic in v0.1; ML model deferred to Phase 1c).
- ~~**Q3 beacon temporal substrate**~~ → DONE (in-memory single-window; TimescaleDB historical baselines = Phase 1c).
- ~~**Q4 multi-cloud**~~ → DONE (AWS-only in v0.1; Azure + GCP land under D.5).

---

## Sign-off

D.4 Network Threat Agent is **production-ready for v0.1 deterministic offline-analysis flows**. The 3-feed concurrent ingest + 3 pure detectors + intel uplift + dual-pin summarizer + dedup pass are all wired and exercised end-to-end via the 10/10 eval gate. ADR-007 v1.1 + v1.2 conformance verified; v1.3 + v1.4 opt-outs confirmed.

**Phase 1b detection track is half-done at M2** — ahead of the original M5-M7 projection. D.4 plus D.7 together close the **CDR + Network** Wiz quadrants, putting weighted coverage at ~34.8%. The remaining Phase-1b work (D.5 multi-cloud CSPM + D.6 K8s posture) is pure pattern application against the now-stable substrate.

**Recommended next plan to write:** **D.5 CSPM extension #1** — Azure + GCP multi-cloud lift. Highest-leverage remaining Phase-1b work (CSPM is the highest-weight Wiz family at 0.40; multi-cloud unlocks ~+10pp).

— recorded 2026-05-13
