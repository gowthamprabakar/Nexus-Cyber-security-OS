# D.3 — Runtime Threat Agent (CWPP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Runtime Threat Agent** (#4 of 18) — Cloud Workload Protection Platform (CWPP). Consumes runtime alerts from eBPF-based sensors (Falco, Tracee) and on-host query engines (OSQuery), normalizes them to OCSF v1.3 Detection Findings, and emits the same shape every other Track-D agent emits. Lives at `packages/agents/runtime-threat/`.

**Strategic role.** D.3 is the **first agent built end-to-end against the post-D.2 canon** — ADR-007 v1.2 (NLAH-loader hoist) just landed, so the agent should ship a 25-line `nlah_loader.py` shim instead of duplicating ~55 LOC. If the shim works without divergence and the agent ships cleanly, **v1.2 is twice-validated** (alongside v1.1 which D.2 twice-validated). **No new architectural decisions are expected** — the canon is locked at v1.2.

D.3 is also the **first runtime-side agent** (the prior three sense static configuration: CSPM, vulnerability scanning, IAM posture). The substrate doesn't change but the input shape does — agents now read **alert streams** rather than calling APIs that return state. The contract-bound budget gets a new dimension (incoming alert volume) that maps onto the existing `cloud_api_calls` budget for v0.1; a dedicated `alerts_consumed` dimension is deferred to Phase 1b once event-volume costs become a real driver.

**Architecture:** Same shape as F.3 / D.1 / D.2. The capability swap is configuration-scanning → runtime-alert-consumption:

```
ExecutionContract (YAML)
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Charter context manager (per F.1 / ADR-002)                  │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Async tool wrappers (per ADR-005)                            │
│   - falco_alerts_read   (JSONL stream → typed alerts)        │
│   - tracee_alerts_read  (JSONL stream → typed alerts)        │
│   - osquery_run         (subprocess; query pack → rows)      │
└──────────────────────────────────────────────────────────────┘
    │ concurrent multi-feed read via asyncio.TaskGroup
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Findings normalizer — alerts + OSQuery rows → OCSF v1.3      │
│   Detection Finding (class_uid 2004) wrapped with            │
│   NexusEnvelope (per ADR-004).                               │
│   Five families: RUNTIME_PROCESS / RUNTIME_FILE /            │
│   RUNTIME_NETWORK / RUNTIME_SYSCALL / RUNTIME_OSQUERY.       │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
findings.json + summary.md + audit.jsonl
    │
    ▼
eval suite (10/10 cases via the F.2 framework)
```

**Tech stack:** Python 3.12 · BSL 1.1 · pydantic 2.9 · `nexus-charter` · `nexus-shared` · `nexus-eval-framework` (workspace deps). **No new HTTP clients** — runtime-threat is filesystem + subprocess at the tool layer. `charter.llm_adapter` handles LLM provider selection per ADR-007 v1.1. `charter.nlah_loader` provides the NLAH-load substrate per ADR-007 v1.2.

**Depends on:**

- F.1 (charter), F.2 (eval framework), ADR-007 v1.2 (post-NLAH-loader-hoist).
- Falco / Tracee / OSQuery are **not bundled** with the agent. The deterministic v0.1 flow reads from JSONL fixtures + OSQuery subprocess; live-stream consumption (gRPC / unix-socket) is Phase 1c.

**Defers (Phase 2+):**

- Live Falco gRPC ingestion (custom Outputs to a long-running streaming consumer) — Phase 1c.
- Kubernetes-native deployment (DaemonSet sidecar wiring) — Phase 1b once the customer envelope clarifies single-cluster vs. multi-cluster scope.
- Windows runtime sensors (Sysmon parsers) — Phase 2 multi-OS.
- MITRE ATT&CK technique mapping per finding — Phase 1b D.8 Threat Intel Agent injects the mapping cross-agent.
- Asset enrichment (which container, which pod, which deployment) — Phase 1b D.7 Investigation Agent owns the enrichment pass.
- Live OSQuery distributed scheduler — Phase 1c.

**Reference template:** [F.3 Cloud Posture](2026-05-08-f-3-cloud-posture-reference-nlah.md) + [D.1 Vulnerability Agent](2026-05-10-d-1-vulnerability-agent.md) + [D.2 Identity Agent](2026-05-11-d-2-identity-agent.md). Don't re-derive what's already there. Three prior agents are all valid templates; D.2 is the most-recent and incorporates ADR-007 v1.1 + v1.2 deltas.

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status     | Commit    | Notes                                                                                                                                                 |
| ---- | ---------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `27c04a3` | Bootstrap `packages/agents/runtime-threat/`; 4 smoke tests including the v1.2 validation gate (`test_charter_nlah_loader_import_works`)               |
| 2    | ✅ done    | `2a3ffd6` | OCSF v1.3 Detection Finding schema (`class_uid 2004`) + 5-bucket FindingType enum; 41 tests; **Q1 resolved** (shared 2004 with D.2)                   |
| 3    | ✅ done    | `2a3ffd6` | `falco_alerts_read` async wrapper — JSONL reader; 12 tests; malformed-line tolerance                                                                  |
| 4    | ✅ done    | `e5b5843` | `tracee_alerts_read` async wrapper — JSONL reader; 11 tests; ns timestamp + args-list flatten + k8s lift                                              |
| 5    | ✅ done    | `e5b5843` | `osquery_run` subprocess wrapper — 10 tests via FakeProcess shim; **Q2 resolved** (all three feeds shipped in v0.1)                                   |
| 6    | ✅ done    | `f97ded0` | Severity normalizer — 3 native scales → internal `Severity`; 25 tests with full-matrix parametrization                                                |
| 7    | ✅ done    | `f97ded0` | Findings normalizer — 5-family dispatch (Falco tags / Tracee event prefix / OSQuery row); 20 tests; no v0.1 dedup (deferred to D.7)                   |
| 8    | ✅ done    | `b785b4a` | Markdown summarizer with critical-alerts pin; 14 tests; parametrized per finding-type rendering                                                       |
| 9    | ✅ done    | `b785b4a` | NLAH bundle + 25-line shim (vs D.1's 55-LOC pre-hoist); 8 tests; **first agent on ADR-007 v1.2 from scratch**                                         |
| 10   | ✅ done    | `b785b4a` | charter.llm_adapter consumed directly; **ADR-007 v1.1 thrice-validated**; no per-agent llm.py exists (anti-pattern guard green)                       |
| 11   | ⬜ pending | —         | Agent driver — async `run()` wires charter + concurrent alert reads + normalizer + summarizer; deterministic v0.1                                     |
| 12   | ⬜ pending | —         | 10 representative eval cases (process suspicion / file tamper / network beacon / OSQuery process tree / multi-finding rollup variants)                |
| 13   | ⬜ pending | —         | `RuntimeThreatEvalRunner` registered via `nexus_eval_runners` entry-point; 10/10 via `eval-framework run --runner runtime_threat`                     |
| 14   | ⬜ pending | —         | CLI: `runtime-threat-agent eval CASES_DIR` + `runtime-threat-agent run --contract path.yaml --falco-feed FILE --tracee-feed FILE --osquery-pack FILE` |
| 15   | ⬜ pending | —         | Package README + runbook (`runbooks/consume_falco_feed.md`) + ADR-007 v1.2 conformance addendum                                                       |
| 16   | ⬜ pending | —         | Final verification (≥ 80% coverage; ruff/mypy clean; CLI smoke; suite-on-suite via F.2; ADR-007 v1.2 confirmed)                                       |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [**ADR-007 v1.2**](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md).

---

## Key design questions (resolve in Tasks 2, 4, 11)

### Q1 — OCSF class for runtime threat findings

D.2 already chose `class_uid 2004` Detection Finding for risky-state findings on principals. Runtime threats are also detections, but the question is whether they should be the same class or a different one.

- **`class_uid 2004` Detection Finding (shared with D.2)** — keeps the wire format uniform; runtime findings differentiated by `finding_info.types[0]` (the `FindingType` enum value).
- **`class_uid 1006` Process Activity / `class_uid 1001` File System Activity / `class_uid 4001` Network Activity** — finer-grained, but mixes activity events (raw OS telemetry) with findings (an analyst's interpretation). OCSF treats these as separate categories.
- **Custom Nexus extension class** — out of scope for ADR-004's "OCSF compatibility non-negotiable" stance.

Resolve in Task 2 by adopting `class_uid 2004`. The OCSF event references the underlying activity records as evidence (e.g., `evidences[0].process` for a Process Activity-shaped sub-doc). This keeps the cross-agent OCSF inventory tight:

| Agent                | OCSF `class_uid` | Class name            |
| -------------------- | ---------------- | --------------------- |
| Cloud Posture        | 2003             | Compliance Finding    |
| Vulnerability        | 2002             | Vulnerability Finding |
| Identity (D.2)       | 2004             | Detection Finding     |
| Runtime Threat (D.3) | 2004             | Detection Finding     |

### Q2 — Falco-only vs. Falco + Tracee + OSQuery in v0.1

The roadmap names all three tools. v0.1 has options:

- **Wire all three from day one** (Falco + Tracee + OSQuery). Risk: three tools' alert shapes to normalize; eval suite needs three fixture flavors. Reward: customer demos work the day the agent ships.
- **Falco-only in v0.1; Tracee + OSQuery wired but unused.** Risk: only validates one alert-shape normalization path; later integration may surface shape issues. Reward: faster ship.
- **Falco + OSQuery (skip Tracee initially).** Falco and Tracee overlap heavily; Tracee is more advanced eBPF but Falco has bigger market share. OSQuery is the orthogonal tool (queries OS state vs. observing events).

Resolve in Task 4. **Recommendation:** ship all three tool wrappers in v0.1 so the deterministic flow exercises every normalization path, but only Falco's fixture appears in 7 of 10 eval cases. Tracee's distinct schema gets ≥ 2 dedicated cases; OSQuery gets ≥ 1 (process tree query).

### Q3 — Alert ingestion model (file fixture vs. live stream)

v0.1 needs deterministic eval suites. Options:

- **JSONL file fixture per feed** (`--falco-feed /path/to/alerts.jsonl`) — read once, process, emit findings. Aligns with the eval-runner's fixture pattern.
- **Live gRPC / unix-socket stream** — what production Falco does. Requires a long-running consumer with backpressure; doesn't fit the v0.1 "scan-and-exit" model.

Resolve in Task 3. **JSONL file fixture in v0.1.** Live-stream consumption defers to Phase 1c when long-running daemon agents land alongside D.12 Curiosity Agent's idle scheduler.

---

## File Structure

```
packages/agents/runtime-threat/
├── pyproject.toml                              # name=nexus-runtime-threat, BSL 1.1
├── README.md
├── LICENSE (BSL 1.1; ../../../LICENSE-BSL)
├── src/runtime_threat/
│   ├── __init__.py
│   ├── py.typed
│   ├── schemas.py                              # OCSF Detection Finding (class_uid 2004)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── falco.py                            # falco_alerts_read async wrapper
│   │   ├── tracee.py                           # tracee_alerts_read async wrapper
│   │   └── osquery.py                          # osquery_run async wrapper (subprocess)
│   ├── normalizer.py                           # per-tool alerts → IdentityFinding-style wrapper
│   ├── summarizer.py                           # render_summary; critical-alerts pinned at top
│   ├── nlah_loader.py                          # 25-line shim importing charter.nlah_loader (ADR-007 v1.2)
│   ├── nlah/
│   │   ├── README.md
│   │   ├── tools.md
│   │   └── examples/
│   │       ├── 01-suspicious-shell-spawn.md
│   │       └── 02-clean-cluster.md
│   ├── agent.py
│   ├── eval_runner.py
│   └── cli.py
├── eval/
│   └── cases/
│       ├── 001_clean_cluster.yaml
│       ├── 002_suspicious_shell_spawn.yaml
│       ├── 003_credential_file_read.yaml
│       ├── 004_outbound_to_tor_exit.yaml
│       ├── 005_kernel_module_loaded.yaml
│       ├── 006_tracee_only_severe.yaml
│       ├── 007_tracee_low_signal.yaml
│       ├── 008_osquery_orphan_process.yaml
│       ├── 009_multi_feed_overlap.yaml         # same incident in Falco + Tracee
│       └── 010_mixed_findings.yaml
├── runbooks/
│   └── consume_falco_feed.md
└── tests/
    ├── test_smoke.py
    ├── test_schemas.py
    ├── test_falco.py
    ├── test_tracee.py
    ├── test_osquery.py
    ├── test_normalizer.py
    ├── test_summarizer.py
    ├── test_nlah_loader.py
    ├── test_agent_unit.py
    ├── test_eval_runner.py
    └── test_cli.py
```

---

## Task 1: Bootstrap

Mirror D.2 Task 1 with the substitution `identity → runtime_threat` and the inherited canon (ADR-007 v1.2). Two things change vs. D.2's bootstrap:

1. The smoke test imports `charter.nlah_loader` AND `charter.llm_adapter` — both v1.1 and v1.2 hoists are validated by smoke before any agent code lands.
2. The pyproject `[project.entry-points."nexus_eval_runners"]` registers `runtime_threat → runtime_threat.eval_runner:RuntimeThreatEvalRunner` (the eval-runner file lands in Task 13; the entry-point can resolve a not-yet-existing import path because uv's editable install is lazy).

- [x] **Step 1: pyproject + scaffold files**.
- [x] **Step 2: workspace member registration** in repo root `pyproject.toml`.
- [x] **Step 3: Smoke tests** — 4 tests landed (one more than planned): package imports + `charter.llm_adapter` + `charter.nlah_loader` + anti-pattern guard for `runtime_threat.llm`.
- [x] **Step 4: Commit** — `27c04a3 feat(d3): plan + bootstrap runtime-threat agent package (D.3 task 1)`. Plan written + Task 1 shipped in the same commit.

---

## Task 2: OCSF Detection Finding schema + FindingType enum

Mirror D.2's `schemas.py` shape. Components:

- `Severity` StrEnum (5 buckets); same mapping to OCSF `severity_id`.
- `FindingType` StrEnum: `RUNTIME_PROCESS`, `RUNTIME_FILE`, `RUNTIME_NETWORK`, `RUNTIME_SYSCALL`, `RUNTIME_OSQUERY`.
- `AffectedHost` pydantic model — replaces D.2's `AffectedPrincipal`. Carries `hostname`, `host_id` (cloud instance id / container id / k8s pod uid), `image_ref`, `node_id`, `ip_addresses`.
- `RuntimeFinding` typed wrapper over the OCSF dict (mirrors D.2's `IdentityFinding`).
- `build_finding(...)` constructor enforcing `FINDING_ID_RE` (`RUNTIME-(PROCESS|FILE|NETWORK|SYSCALL|OSQUERY)-[A-Z0-9]+-NNN-<context>`).
- `FindingsReport` aggregate with `count_by_severity()` + `count_by_finding_type()`.

- [ ] **Step 1: Write failing tests** — ≥ 15 tests covering severity round-trip, finding-id regex, envelope wrap/unwrap, frozen-dataclass invariants.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): ocsf detection finding schema + 5-bucket finding-type enum (D.3 task 2)`.

**Resolves Q1.** Records the OCSF class table in the module docstring (matches D.2's pattern).

---

## Task 3: `falco_alerts_read` async wrapper

Falco emits JSONL alerts. Each line:

```json
{
  "time": "2026-05-11T12:00:00.123Z",
  "rule": "Terminal shell in container",
  "priority": "Warning",
  "output": "A shell was used as the entrypoint/exec point ...",
  "output_fields": {
    "container.id": "abc123",
    "container.image.repository": "nginx",
    "proc.cmdline": "/bin/sh",
    "proc.pid": 4242,
    "user.name": "root",
    "k8s.pod.name": "frontend-7f9d-abcde",
    "k8s.ns.name": "production"
  },
  "tags": ["container", "shell", "process", "mitre_execution"]
}
```

Signature:

```python
async def falco_alerts_read(
    *,
    feed_path: Path | str,
    timeout_sec: float = 60.0,
) -> tuple[FalcoAlert, ...]:
```

Tolerates malformed lines (logs + skips, doesn't raise). Returns `tuple[FalcoAlert, ...]` — frozen dataclass with `time`, `rule`, `priority`, `output`, `output_fields: dict[str, Any]`, `tags: tuple[str, ...]`.

- [ ] **Step 1: Write failing tests** — ≥ 8 tests; happy path, multiple alerts, empty file, malformed line in middle, missing file → `FalcoError`.
- [ ] **Step 2: Implement** (async via `asyncio.to_thread` for the file read).
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): falco alerts json-lines reader (D.3 task 3)`.

---

## Task 4: `tracee_alerts_read` async wrapper

Tracee's schema overlaps with Falco but differs. Each alert:

```json
{
  "timestamp": 1715414400000000000,
  "eventName": "security_file_open",
  "processName": "cat",
  "hostName": "ip-10-0-1-42",
  "containerImage": "alpine:3.18",
  "args": [{ "name": "pathname", "value": "/etc/shadow" }],
  "metadata": {
    "Severity": 3,
    "Description": "Read sensitive credential file"
  },
  "kubernetes": { "podName": "ssh-bastion-x", "namespace": "kube-system" }
}
```

Signature:

```python
async def tracee_alerts_read(
    *,
    feed_path: Path | str,
    timeout_sec: float = 60.0,
) -> tuple[TraceeAlert, ...]:
```

Returns frozen `TraceeAlert` with `timestamp` (datetime, ns→μs conversion), `event_name`, `process_name`, `host_name`, `container_image`, `args: dict[str, str]`, `severity: int`, `description`, `pod_name`, `namespace`.

**Resolves Q2.** The plan ships all three tool wrappers (Falco + Tracee + OSQuery) in v0.1.

- [ ] **Step 1: Write failing tests** — ≥ 6 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): tracee alerts json-lines reader (D.3 task 4)`.

---

## Task 5: `osquery_run` async wrapper

OSQuery is invoked via `osqueryi --json` against a SQL query pack. v0.1 reads canned `osqueryi` output (subprocess captured); live invocation is gated on the binary being present.

Signature:

```python
async def osquery_run(
    *,
    sql: str,
    timeout_sec: float = 30.0,
    osqueryi_binary: str = "osqueryi",
) -> OsqueryResult:
```

Returns `OsqueryResult(sql, rows: tuple[dict[str, str], ...], ran_at: datetime)`.

- [ ] **Step 1: Write failing tests** — ≥ 5 tests; happy path with mocked subprocess; binary not found → `OsqueryError`; malformed JSON → `OsqueryError`; timeout.
- [ ] **Step 2: Implement** via `asyncio.create_subprocess_exec` per ADR-005.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): osquery subprocess runner (D.3 task 5)`.

---

## Task 6: Severity normalizer

Three input shapes, one output:

| Tool    | Native severity scale                                                                       | OCSF `severity_id` mapping                     |
| ------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Falco   | `priority`: Emergency / Alert / Critical / Error / Warning / Notice / Informational / Debug | 5 / 5 / 5 / 4 / 3 / 2 / 1 / 1                  |
| Tracee  | `Severity`: integer 0–3                                                                     | 0 = info / 1 = low / 2 = medium / 3 = critical |
| OSQuery | n/a — operator-supplied per query                                                           | Query-pack metadata sets it explicitly         |

- [ ] **Step 1: Write failing tests** — ≥ 12 parametrized tests across the three scales.
- [ ] **Step 2: Implement** as a small pure module (`severity.py`) with three `falco_to_severity()` / `tracee_to_severity()` / `osquery_to_severity()` functions.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): severity normalizer across falco/tracee/osquery (D.3 task 6)`.

---

## Task 7: Findings normalizer

Mirror D.2's `normalizer.py`. Inputs: `falco_alerts` + `tracee_alerts` + `osquery_results`. Output: `list[RuntimeFinding]`.

Per-tool emission:

- **Falco alerts** → `FindingType` chosen from the alert's `tags` (e.g., tag `process` → `RUNTIME_PROCESS`; tag `network` → `RUNTIME_NETWORK`; tag `filesystem` → `RUNTIME_FILE`; tag `syscall` → `RUNTIME_SYSCALL`). Default `RUNTIME_PROCESS`.
- **Tracee alerts** → `FindingType` from `eventName` prefix (`security_file_*` → `RUNTIME_FILE`; `security_socket_*` → `RUNTIME_NETWORK`; otherwise → `RUNTIME_SYSCALL`).
- **OSQuery rows** → one `RUNTIME_OSQUERY` finding per row.

Severity comes from Task 6's normalizer.

- [ ] **Step 1: Write failing tests** — ≥ 12 tests: per-tool fixtures, multi-tool dedup (when Falco + Tracee describe the same event), empty-input path, OSQuery-only path, severity propagation.
- [ ] **Step 2: Implement** as `async def normalize_to_findings(...)` mirroring D.2's shape (async seam; body sync because all inputs are pre-loaded).
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): runtime findings normalizer with 5 detection types (D.3 task 7)`.

---

## Task 8: Markdown summarizer

Mirror D.2's `summarizer.py`. Pin a "Critical runtime alerts" section above the per-severity sections — any finding with `severity == CRITICAL` lands there (mirrors D.1's KEV section and D.2's high-risk-principals pin).

- [ ] **Step 1: Write failing tests** — ≥ 8 tests; empty + each finding type + multi-finding rollup + severity ordering.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): markdown summarizer with critical-alerts pin (D.3 task 8)`.

---

## Task 9: NLAH bundle + `charter.nlah_loader` shim

**The ADR-007 v1.2 validation gate.** Ship a 25-line shim that imports `charter.nlah_loader` (binding `__file__` for the agent's `nlah/` dir) plus the NLAH content (README + tools.md + 2 examples).

- [ ] **Step 1: Write the four NLAH content files**.
- [ ] **Step 2: Write the shim** — identical structure to D.2's post-v1.2 shim; only the module docstring's package name differs.
- [ ] **Step 3: Loader test** — copy-with-rename of D.2's `test_nlah_loader.py` (8 tests). The tests exercise the shim, which delegates to `charter.nlah_loader`.
- [ ] **Step 4: Commit** — `feat(d3): nlah bundle + charter.nlah_loader shim (D.3 task 9)`.

**Pattern check:** the shim is ~25 LOC vs. D.1's original ~55 LOC nlah_loader. **This is what ADR-007 v1.2 buys** — confirm the savings land in the commit message.

---

## Task 10: LLM adapter — `from charter.llm_adapter import ...`

Mirror D.2's Task 10. Smoke test already validates the import in Task 1; the **anti-pattern guard test** (`importlib.util.find_spec("runtime_threat.llm") is None`) confirms no per-agent `llm.py` accidentally lands.

- [ ] **Step 1: Confirm via smoke** — already covered in Task 1.
- [ ] **Step 2: Anti-pattern guard test** — copy-with-rename of D.2's `test_no_per_agent_llm_module`.
- [ ] **Step 3: Commit** — `chore(d3): consume charter.llm_adapter (D.3 task 10; adr-007 v1.1 thrice-validated)`.

---

## Task 11: Agent driver

Mirror D.2's [`agent.py`](../../../packages/agents/identity/src/identity/agent.py). The flow:

1. Charter context manager.
2. Concurrent fetch of (Falco alerts) + (Tracee alerts) + (OSQuery results) via `asyncio.TaskGroup`. Any feed with no source path skips cleanly.
3. Normalizer → OCSF findings.
4. `findings.json` + `summary.md` written via `ctx.write_output`.
5. Charter exits → `assert_complete`.

Signature:

```python
async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,
    falco_feed: Path | str | None = None,
    tracee_feed: Path | str | None = None,
    osquery_pack: Path | str | None = None,
) -> FindingsReport:
```

When all three inputs are `None`, the agent emits an empty report and writes empty outputs (matches D.2's empty-account behavior).

- [ ] **Step 1: Write failing tests** — ≥ 12 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): agent driver wiring charter + multi-feed reads (D.3 task 11)`.

---

## Task 12: 10 representative eval cases

| #   | Title                  | Fixture                                                                 | Expected                                           |
| --- | ---------------------- | ----------------------------------------------------------------------- | -------------------------------------------------- |
| 001 | clean_cluster          | empty Falco + Tracee + OSQuery feeds                                    | 0 findings                                         |
| 002 | suspicious_shell_spawn | Falco "Terminal shell in container" alert                               | 1 high finding (RUNTIME_PROCESS)                   |
| 003 | credential_file_read   | Tracee `security_file_open` on `/etc/shadow`                            | 1 critical finding (RUNTIME_FILE)                  |
| 004 | outbound_to_tor_exit   | Falco "Outbound connection to suspicious IP" alert                      | 1 critical finding (RUNTIME_NETWORK)               |
| 005 | kernel_module_loaded   | Falco "Unauthorized kernel module load" alert                           | 1 critical finding (RUNTIME_SYSCALL)               |
| 006 | tracee_only_severe     | Tracee-only alert with `Severity: 3`                                    | 1 critical finding                                 |
| 007 | tracee_low_signal      | Tracee-only alert with `Severity: 1`                                    | 1 low finding                                      |
| 008 | osquery_orphan_process | OSQuery row showing a process with `parent_pid` not in the process list | 1 medium finding (RUNTIME_OSQUERY)                 |
| 009 | multi_feed_overlap     | Same incident reported by Falco AND Tracee                              | 2 findings (no dedup in v0.1; deferred to Phase 2) |
| 010 | mixed_findings         | One alert per family + one OSQuery row                                  | 5 findings, correct family rollup                  |

- [ ] **Step 1: Write the 10 YAML files.**
- [ ] **Step 2: Iterate fixtures** until 10/10 pass via Task 13's runner.
- [ ] **Step 3: Commit** — `feat(d3): 10 representative eval cases (D.3 task 12)`.

---

## Task 13: `RuntimeThreatEvalRunner` + entry-point

Mirror D.2's [`eval_runner.py`](../../../packages/agents/identity/src/identity/eval_runner.py). Patches `agent_mod.falco_alerts_read`, `agent_mod.tracee_alerts_read`, `agent_mod.osquery_run` per `case.fixture`. Comparison shape: `finding_count` / `by_severity` / `by_finding_type`.

`pyproject.toml`:

```toml
[project.entry-points."nexus_eval_runners"]
runtime_threat = "runtime_threat.eval_runner:RuntimeThreatEvalRunner"
```

- [ ] **Step 1: Write failing tests** — Protocol satisfaction + happy + mismatch + 10/10 acceptance gate.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Verify entry-point** — `uv run eval-framework run --runner runtime_threat --cases ... --output ...` prints `10/10 passed`.
- [ ] **Step 4: Commit** — `feat(d3): runtimethreatevalrunner against the eval-framework (D.3 task 13)`.

---

## Task 14: CLI

Mirror D.2's [`cli.py`](../../../packages/agents/identity/src/identity/cli.py). Two subcommands:

- `runtime-threat-agent eval CASES_DIR`
- `runtime-threat-agent run --contract path.yaml [--falco-feed FILE] [--tracee-feed FILE] [--osquery-pack FILE]`

- [ ] **Step 1: Write failing tests** via Click's CliRunner — ≥ 5 tests.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(d3): cli with eval + run subcommands (D.3 task 14)`.

---

## Task 15: README + runbook + ADR-007 v1.2 conformance

README pattern from D.2. Runbook is `runbooks/consume_falco_feed.md` — walks an operator through pointing the agent at a real Falco JSONL feed (file-tail or batch-import).

ADR-007 v1.2 conformance addendum:

| Pattern (10 in canon)                 | D.3 verdict                                         |
| ------------------------------------- | --------------------------------------------------- |
| Schema-as-typing-layer                | Task 2                                              |
| Async-by-default tool wrappers        | Tasks 3 + 4 + 5                                     |
| HTTP-wrapper convention               | n/a (filesystem + subprocess)                       |
| Concurrent TaskGroup enrichment       | Task 11                                             |
| Markdown summarizer                   | Task 8                                              |
| NLAH layout                           | Task 9 — **ADR-007 v1.2 validation** (~25 LOC shim) |
| LLM adapter via `charter.llm_adapter` | Task 10 — **thrice-validated**                      |
| Charter context + agent.run shape     | Task 11                                             |
| Eval-runner via entry-point group     | Task 13                                             |
| CLI subcommand pattern                | Task 14                                             |

- [ ] **Step 1: Write README + runbook + addendum.**
- [ ] **Step 2: Commit** — `docs(d3): readme + runbook + adr-007 v1.2 conformance (D.3 task 15)`.

---

## Task 16: Final verification

Mirror D.2's gate set:

1. `uv run pytest packages/agents/runtime-threat/ --cov=runtime_threat --cov-fail-under=80` — ≥ 80%.
2. `uv run ruff check + format --check + mypy strict` — all clean.
3. `uv run runtime-threat-agent eval packages/agents/runtime-threat/eval/cases` — `10/10 passed`.
4. `uv run eval-framework run --runner runtime_threat --cases ... --output suite.json` — same.
5. `uv run eval-framework gate suite.json --config <(echo 'min_pass_rate: 1.0')` — exit 0.
6. **ADR-007 v1.2 conformance review** — confirm both v1.1 (LLM adapter) and v1.2 (NLAH loader) hoists landed correctly; no `runtime_threat/llm.py`; `nlah_loader.py` is the 25-line shim.

Capture `docs/_meta/d3-verification-<date>.md`.

- [ ] **Step 1: Run all gates.**
- [ ] **Step 2: Write verification record.**
- [ ] **Step 3: Commit** — `docs(d3): final verification + adr-007 v1.2 confirmation`.

**Acceptance:** Runtime Threat Agent runs end-to-end against the eval framework. ADR-007 v1.2 confirmed (3 agents now on the post-amendment canon). Any new amendment recommendations queued for ADR-007 v1.3 before D.4.

---

## Self-Review

**Spec coverage** (build-roadmap entry "Falco (eBPF), Tracee, OSQuery"):

- ✓ Falco — Task 3 (JSONL reader).
- ✓ Tracee — Task 4 (JSONL reader).
- ✓ OSQuery — Task 5 (subprocess runner).

**Phase-1a caps (deferred):**

- ✓ Live Falco gRPC (Phase 1c).
- ✓ Kubernetes DaemonSet wiring (Phase 1b).
- ✓ Windows runtime sensors (Phase 2).
- ✓ MITRE ATT&CK technique mapping (Phase 1b; cross-agent via D.8 Threat Intel).
- ✓ Asset enrichment (Phase 1b; via D.7 Investigation).
- ✓ Live OSQuery distributed scheduler (Phase 1c).

**Pattern parity vs D.1 / D.2:**

- ✓ 16-task structure preserved.
- ✓ 10-case eval gate preserved.
- ✓ Identical Q-decision discipline (3 questions resolved in code, recorded in task commits).
- ✓ Reference template includes D.2 alongside F.3 / D.1 — three valid prior agents.

**What's different from D.2:**

- **First agent on ADR-007 v1.2 from day one.** NLAH loader is a 25-line shim, not a 55-line copy. LLM adapter is a direct import, not a per-agent module. Validates that the v1.2 amendment was correctly sized.
- **Input shape is alert streams, not API state.** The substrate doesn't change (charter / OCSF / NexusEnvelope all identical) but the eval-fixture pattern shifts from "mock the SDK call" to "stage a JSONL fixture file."
- **Three feeds instead of three APIs.** TaskGroup concurrency pattern preserved; the fan-out is the same.

**Acceptance gates (carry-forward from D.2):**

- ≥ 80% coverage at Task 16.
- ruff + format + mypy strict clean across the new package.
- 10/10 eval pass via the framework CLI.
- `charter.llm_adapter` + `charter.nlah_loader` imports work without any per-agent re-export.
- ADR-007 v1.2 conformance review surfaces no new amendments (or queues v1.3 candidates explicitly).
