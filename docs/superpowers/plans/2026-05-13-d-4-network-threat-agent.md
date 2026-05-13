# D.4 — Network Threat Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Network Threat Agent** (`packages/agents/network-threat/`), **Agent #6** per the [agent spec](../../agents/agent_specification_with_harness.md#agent-6--network-threat-agent). The **second Phase-1b agent** and the **seventh agent under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / **D.4**). Mirrors D.3's three-feed pattern, applied to the network domain instead of the workload domain.

**Three-feed shape (mirrors D.3):**

- **Suricata** — rule-based IDS alert ndjson (read from filesystem; offline-mode in v0.1).
- **VPC Flow Logs v5** — AWS native flow records (operator-pinned filesystem source; cloud-native API integration in Phase 1c).
- **DNS logs** — BIND query log + AWS Route 53 Resolver Query Logs (operator-pinned filesystem source).

**v0.1 emits forensic findings** (offline analysis). Tier-1 IP-blocking action (`block_ip_at_waf` per the agent spec) is **deferred to Phase 1c** — it needs the WAF integration substrate that Track-A remediation will land, and the v1.3 "always-on" pattern doesn't fit (block actions are budget-axis-sensitive, not budget-axis-overridable).

**Strategic role.** Second Phase-1b agent; first agent to consume **D.7's incident-correlation contract** automatically (each D.4 finding flows through D.7 with no extra wiring). Closes a key gap in the Wiz-equivalence story: pure CSPM (F.3, D.1) doesn't catch network-borne threats; D.4 is the first agent to surface beacon / DGA / port-scan signals.

**Q1 (resolve up-front).** OCSF class selection. Two candidates:

- **OCSF 2004 Detection Finding** — D.2 + D.3 use this; consistent for `types[0]="network_threat"` discriminator pattern.
- **OCSF 4001 Network Activity** — observation-shaped, not finding-shaped. The raw VPC flow log records are 4001-shaped but D.4 doesn't emit them — it emits **findings derived from them**.

**Resolution: ship under `2004 Detection Finding` with `types[0]="network_threat"` as the discriminator.** Mirrors D.2 + D.3 + (incident-discriminator path D.7 evaluated then plan-corrected). The 4001 observation stays in the parsed-input layer; D.4's wire output is the finding.

**Q2 (resolve up-front).** DGA detection — ML model vs. heuristic.

- **ML model** (e.g. character-LSTM or random-forest on n-gram features) — the agent spec calls for this; F1 ≥ 0.9 is industry-norm.
- **Entropy + n-gram heuristic** — no model dependency; fully deterministic; explainable to operators.

**Resolution: ship the heuristic in v0.1; defer the ML model to Phase 1c.** Two reasons: (1) the ML model is the agent spec's "F2: DGA model unavailable → use entropy-based heuristic" fallback — landing the fallback first ensures the deterministic path is well-tested before the ML wraps it; (2) shipping the heuristic now keeps D.4 substrate-only (no model artifact, no inference runtime), matching the F.3 → D.3 cadence.

**Q3 (resolve up-front).** Beacon detection — temporal-analysis substrate. The agent spec calls for "periodicity analysis" of repeated connections from one source to one destination. This requires a sliding window over flow records; F.5 has no time-series primitives.

**Resolution: in-memory periodicity scan over the input flow records in a single agent invocation.** No persistence-layer time-series in v0.1. The operator pins a flow-log time window via the contract (`--since` / `--until`); D.4 reads it, groups by (src, dst), computes inter-arrival-time variance + period, and flags low-variance / high-count pairs as beacons. Phase 1c can layer a TimescaleDB-backed historical baseline; v0.1 is single-window.

**Q4 (resolve up-front).** Multi-cloud — AWS only or Azure/GCP too?

**Resolution: AWS only in v0.1.** Per F.3's precedent (AWS-only at v0.1, Azure/GCP queued as D.5). VPC Flow Logs v5 is AWS-specific; Azure NSG Flow Logs and GCP VPC Flow Logs have different schemas. Multi-cloud parser is a Phase 1c lift via a normalizer adapter.

**Architecture:**

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Network Threat Agent driver                                       │
│                                                                   │
│  Stage 1: INGEST         — three feeds concurrent (TaskGroup)     │
│  Stage 2: PATTERN_DETECT — port scans, beacons, DGA queries       │
│  Stage 3: ENRICH         — bundled static threat-intel only       │
│  Stage 4: SCORE          — composite per finding (deterministic)  │
│  Stage 5: SUMMARIZE      — narrative via charter.llm_adapter      │
│  Stage 6: HANDOFF        — emit `findings.json` + `report.md`     │
└─────────┬─────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  read_suricata_alerts   ─→ ndjson parser (alert / fileinfo / dns) │
│  read_vpc_flow_logs     ─→ AWS Flow Logs v5 (filesystem)          │
│  read_dns_logs          ─→ BIND query log + Route53 Resolver fmt  │
│  detect_port_scan       ─→ connection-rate heuristic              │
│  detect_beacon          ─→ periodicity analysis (in-memory)       │
│  detect_dga             ─→ entropy + n-gram heuristic             │
│  enrich_with_intel      ─→ bundled static feed (CISA KEV-style)   │
│  summarize_to_markdown  ─→ pinned beacons/DGA above per-section   │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack:** Python 3.12 · BSL 1.1 · OCSF v1.3 Detection Finding (`class_uid 2004`, `types[0]="network_threat"`) · pydantic 2.9 · click 8 · `charter.llm_adapter` (ADR-007 v1.1) · `charter.nlah_loader` (ADR-007 v1.2). No external network dependencies; offline-mode v0.1.

**Depends on:**

- F.1 charter — standard budget caps; no extensions needed (D.4 is not always-on, not sub-agent-spawning).
- F.4 control-plane — tenant context propagates through the contract.
- F.5 memory engines — `EpisodicStore` for per-run finding persistence (optional in v0.1; landed lazily).
- F.6 Audit Agent — every D.4 run emits an audit chain via `charter.audit.AuditLog`.
- ADR-007 v1.1 + v1.2 — reference NLAH template. D.4 is the **seventh** agent under it. v1.3 (always-on) opt-out; v1.4 (sub-agent spawning) not consumed.

**Defers (Phase 1c / Phase 2):**

- **Tier-1 block actions** (`block_ip_at_waf`) — Phase 1c (needs Track-A remediation substrate).
- **Cloud-native flow log APIs** (boto3 `ec2.describe_flow_logs` + live S3 → Athena) — Phase 1c. v0.1 reads pre-fetched filesystem sources.
- **DGA ML model** (character-LSTM on Alexa-1M vs. DGArchive) — Phase 1c. v0.1 ships the entropy + n-gram heuristic.
- **TimescaleDB historical baselines** for beacon detection — Phase 1c. v0.1 is single-window in-memory.
- **Azure + GCP flow log parsers** — D.5 (CSPM extension #1 covers the multi-cloud lift in one place).
- **Real-time streaming ingest** (Kafka / NATS from edge agents) — Phase 1c. v0.1 is run-on-demand.

**Reference template:** D.3 Runtime Threat Agent (closest match: three-feed concurrent ingest + per-detector pipeline + pinned-above markdown summarizer). D.4 is structurally D.3 with: (a) network feeds (Suricata / VPC FL / DNS) instead of workload feeds (Falco / Tracee / OSQuery); (b) three detectors (port_scan / beacon / dga) instead of three rule classes; (c) **no sub-agent spawning** (D.4 is single-driver — D.7 is the orchestrator agent, not D.4); (d) **non-load-bearing LLM** (deterministic detectors do the work; the LLM only renders the narrative — contrast with D.7 where LLM is load-bearing for hypothesis generation).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status     | Commit    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ---- | ---------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `ed62347` | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework — **no** nexus-audit-agent: D.4 emits its own chain via `charter.audit.AuditLog`, doesn't consume sibling chains). `network-threat` CLI + `network_threat` eval-runner entry-points declared. 9 smoke tests: ADR-007 v1.1 + v1.2 + F.1 audit log + F.5 episodic + 2 anti-pattern guards + 2 entry-point checks. Repo-wide 1349 passed / 11 skipped. |
| 2    | ✅ done    | `4d67586` | OCSF schemas — Detection Finding 2004 with `types[0]="network_threat"`. 6 pydantic models (NetworkFinding / FlowRecord / DnsEvent / SuricataAlert / Beacon / Detection) + AffectedNetwork + FindingType (4 buckets) + Severity round-trip + build_finding + FindingsReport. Q1 confirmed (2004); Q6 dedup_key() lands as `Detection.dedup_key()`. 45 tests; mypy strict clean; repo-wide 1394 passed / 11 skipped.            |
| 3    | ✅ done    | `c7ad964` | `read_suricata_alerts` — ndjson parser; alert event_type only (dns/flow/http/tls/fileinfo deferred to their readers); forgiving on malformed lines; handles both `Z` and `+0000` ISO-8601; flow_id/community_id preserved under `unmapped`. 10 tests. Repo-wide 1414 passed / 11 skipped.                                                                                                                                     |
| 4    | ✅ done    | `c7ad964` | `read_vpc_flow_logs` — AWS Flow Logs v2/v3/v4/v5 superset; header-driven field map (v5 with vpc-id) with v2 14-field default fallback; gzip + plaintext (magic-bytes detection); `-` → 0 for numerics; trailing extras under `unmapped.extra_<i>`. 10 tests. (Co-shipped with Task 3.)                                                                                                                                        |
| 5    | ⬜ pending | —         | `read_dns_logs` tool — BIND query log + Route 53 Resolver Query Logs JSON format; async; multi-format dispatch.                                                                                                                                                                                                                                                                                                               |
| 6    | ⬜ pending | —         | `detect_port_scan` pure function — connection-rate heuristic over flow records; >50 distinct dst-ports / src / 60s → flag.                                                                                                                                                                                                                                                                                                    |
| 7    | ⬜ pending | —         | `detect_beacon` pure function — periodicity analysis (inter-arrival variance + count threshold); in-memory single-window.                                                                                                                                                                                                                                                                                                     |
| 8    | ⬜ pending | —         | `detect_dga` pure function — Shannon entropy + character bigram heuristic; explainable score + components.                                                                                                                                                                                                                                                                                                                    |
| 9    | ⬜ pending | —         | `enrich_with_intel` — bundled static intel (top-100 known C2 domains + CISA KEV IP set). `data/intel_static.json`.                                                                                                                                                                                                                                                                                                            |
| 10   | ⬜ pending | —         | NLAH bundle + 21-LOC shim. ADR-007 v1.2 conformance (4th native v1.2 agent after D.3 / F.6 / D.7). README + tools.md + 2 examples (beacon + DGA-domain).                                                                                                                                                                                                                                                                      |
| 11   | ⬜ pending | —         | `summarize_to_markdown` — pinned beacons/DGA above per-section; mirrors F.6 tamper-alert pin + D.3 critical-runtime pin.                                                                                                                                                                                                                                                                                                      |
| 12   | ⬜ pending | —         | Agent driver `run()` — 6-stage pipeline (INGEST → PATTERN_DETECT → ENRICH → SCORE → SUMMARIZE → HANDOFF). TaskGroup fan-out across the three feeds.                                                                                                                                                                                                                                                                           |
| 13   | ⬜ pending | —         | 10 representative YAML eval cases: clean / port_scan / beacon_low_var / beacon_high_var / dga_high_entropy / dga_low_entropy / mixed / empty / corrupt / multi-source merge.                                                                                                                                                                                                                                                  |
| 14   | ⬜ pending | —         | `NetworkThreatEvalRunner` + `nexus_eval_runners` entry-point + 10/10 acceptance via `eval-framework run --runner network_threat`.                                                                                                                                                                                                                                                                                             |
| 15   | ⬜ pending | —         | CLI (`network-threat eval` / `network-threat run`). Three filter axes: `--since`, `--until`, `--src-cidr`. Output: `findings.json` + `report.md`.                                                                                                                                                                                                                                                                             |
| 16   | ⬜ pending | —         | README + operator runbook (`runbooks/network_triage.md`). ADR-007 v1.1 + v1.2 conformance verified; v1.3 opt-out; v1.4 not consumed. Final verification record `docs/_meta/d4-verification-<date>.md`.                                                                                                                                                                                                                        |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md).

---

## Resolved questions

| #   | Question                                          | Resolution                                                                                                                                                                | Task    |
| --- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| Q1  | Which OCSF class_uid for network-threat findings? | **2004 Detection Finding** with `types[0]="network_threat"` discriminator (mirrors D.2 + D.3). Raw VPC FL records are 4001-shaped but stay internal.                      | Task 2  |
| Q2  | DGA detection — ML model vs. heuristic?           | **Entropy + n-gram heuristic in v0.1.** The agent spec's "F2: model unavailable → heuristic" fallback is the path we ship first; ML model is Phase 1c.                    | Task 8  |
| Q3  | Beacon detection — historical baseline?           | **Single-window in-memory** in v0.1. Operator pins the time window via contract; D.4 computes periodicity over what's in the window. Phase 1c adds TimescaleDB baselines. | Task 7  |
| Q4  | Multi-cloud?                                      | **AWS only in v0.1** (mirrors F.3 precedent). Azure + GCP flow log parsers ship under D.5.                                                                                | Task 4  |
| Q5  | Tier-1 block action (`block_ip_at_waf`)?          | **Deferred to Phase 1c.** Needs Track-A WAF substrate. v0.1 emits findings only — operator routes to a WAF playbook out-of-band.                                          | —       |
| Q6  | Cross-feed merge — how to dedupe findings?        | **Composite key**: `(detection_type, src_cidr, dst_cidr, time_bucket_5m)`. Two detectors flagging the same beacon from the same src dedupe to one finding.                | Task 12 |

---

## File map (target)

```
packages/agents/network-threat/
├── pyproject.toml                              # Task 1
├── README.md                                   # Tasks 1, 16
├── runbooks/
│   └── network_triage.md                       # Task 16
├── src/network_threat/
│   ├── __init__.py                             # Task 1
│   ├── py.typed                                # Task 1
│   ├── schemas.py                              # Task 2 (OCSF 2004 + network_threat discriminator)
│   ├── nlah_loader.py                          # Task 10 (21-LOC shim)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── suricata_reader.py                  # Task 3
│   │   ├── vpc_flow_reader.py                  # Task 4
│   │   └── dns_log_reader.py                   # Task 5
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── port_scan.py                        # Task 6
│   │   ├── beacon.py                           # Task 7
│   │   └── dga.py                              # Task 8
│   ├── enrichment.py                           # Task 9
│   ├── summarizer.py                           # Task 11
│   ├── agent.py                                # Task 12 (driver: 6-stage pipeline)
│   ├── eval_runner.py                          # Task 14
│   └── cli.py                                  # Task 15
├── nlah/
│   ├── README.md                               # Task 10
│   ├── tools.md                                # Task 10
│   └── examples/                               # Task 10 (2 examples: beacon + DGA)
├── data/
│   └── intel_static.json                       # Task 9 (bundled static threat intel)
├── eval/
│   └── cases/                                  # Task 13 (10 YAML cases)
└── tests/
    ├── test_pyproject.py                       # Task 1
    ├── test_schemas.py                         # Task 2
    ├── test_tools_suricata_reader.py           # Task 3
    ├── test_tools_vpc_flow_reader.py           # Task 4
    ├── test_tools_dns_log_reader.py            # Task 5
    ├── test_detectors_port_scan.py             # Task 6
    ├── test_detectors_beacon.py                # Task 7
    ├── test_detectors_dga.py                   # Task 8
    ├── test_enrichment.py                      # Task 9
    ├── test_nlah_loader.py                     # Task 10
    ├── test_summarizer.py                      # Task 11
    ├── test_agent.py                           # Task 12
    ├── test_eval_runner.py                     # Task 14 (incl. 10/10 acceptance)
    └── test_cli.py                             # Task 15
```

---

## Risks

| Risk                                                                                                                 | Mitigation                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| DGA heuristic produces > 5% false-positive rate against legitimate long-domain names (CDN edge nodes, AWS internal). | Bundle an allowlist of `cloudfront.net` / `amazonaws.com` / `akamai.net` / `cloudflare.com` / etc. into `data/intel_static.json`. Detector skips entropy scoring for matched suffixes. Track the FPR in eval Case 5/6 (low-entropy legit-CDN domains). |
| Beacon detection misses bursty patterns (e.g. weekly C2 check-in) because v0.1 is single-window.                     | Document this explicitly in the README + runbook. The heuristic catches sub-window beacons (≤ time-window inter-arrival); cross-window beacons are Phase 1c (TimescaleDB historical baselines).                                                        |
| VPC Flow Logs v5 parser locks in too early; v6 ships when AWS releases a new field.                                  | Field count in the parser is `>= 14` (covers v3, v4, v5); unknown trailing fields stored under `unmapped`. Mirrors the OCSF wire-format pattern.                                                                                                       |
| Suricata rule false-positives drown the report.                                                                      | Summarizer pins beacons + DGA-domain findings **above** Suricata alerts (mirrors F.6 tamper-pin); operators see the high-confidence deterministic detections first, Suricata-only findings second.                                                     |
| Bundled static intel goes stale (CISA KEV IP set + C2 domain list change weekly).                                    | Ship a `data/intel_static.json` updater under Phase 1c (cron-pulled). v0.1 ships a snapshot; the README explicitly notes the snapshot date.                                                                                                            |

---

## Done definition

D.4 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/network-threat` (gate same as D.3 / D.7).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner network_threat` returns 10/10.
- ADR-007 v1.1 + v1.2 conformance verified end-to-end.
- README + runbook reviewed.
- D.4 verification record committed.

That closes the second Phase-1b agent. D.5 (CSPM extension #1, multi-cloud) and D.6 (CSPM extension #2, Kubernetes posture) follow at the same cadence — both pure pattern application against the now-validated substrate + D.7 incident-correlation.

---

## Next plans queued (for context)

- **D.5 CSPM extension #1** — Azure + GCP flow log parsers (lifts the v0.1 multi-cloud deferral); Microsoft Defender for Cloud signal merge.
- **D.6 CSPM extension #2** — Kubernetes posture (CIS benchmark + Polaris); reads kubeconfig + cluster API directly.

D.4 → D.5 → D.6 closes Phase 1b detection. Phase 1c brings A.1–A.3 remediation (Tier 1/2/3 action substrate) + A.4 Meta-Harness + streaming ingest, at which point D.4's `block_ip_at_waf` action ships.
