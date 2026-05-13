# `nexus-network-threat-agent`

Network Threat Agent — agent **#6 of 18** for Nexus Cyber OS. **Second Phase-1b agent** and the **seventh under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / **D.4**). Mirrors D.3's three-feed pattern, applied to the network domain instead of the workload domain.

## What it does

Three-feed offline forensic analysis. Given an `ExecutionContract` requesting a network-threat scan over a pinned time window, D.4 runs a **six-stage pipeline**:

```
INGEST → PATTERN_DETECT → ENRICH → SCORE → SUMMARIZE → HANDOFF
```

Three concurrent input feeds (`asyncio.TaskGroup`):

- **Suricata** — eve.json alert ndjson; alerts only (DNS/flow/http/tls/fileinfo routed elsewhere).
- **AWS VPC Flow Logs v5** — v2/v3/v4/v5 superset; gzipped + plaintext; header-driven field map.
- **DNS logs** — BIND `named` query log + AWS Route 53 Resolver Query Logs (first-line peek auto-dispatches).

Three deterministic detectors:

- `port_scan` — connection-rate heuristic; ≥50 distinct dst-ports / src / 60s → flag; severity scales 50/100/200.
- `beacon` — periodicity analysis per `(src,dst,port)`; low coefficient-of-variation + ≥5 connections → flag; severity scales count + CoV.
- `dga` — Shannon entropy + Norvig top-50 bigram heuristic on the second-level label; severity HIGH at entropy≥4.0 + bigram≤0.05. Bundled CDN/cloud suffix allowlist (CloudFront, S3, Google, Azure, Fastly, Cloudflare) suppresses obvious false positives.

Plus a **lift** for Suricata alerts (each Suricata alert becomes a `NETWORK-SURICATA` Detection with severity preserved).

Then **enrichment**: each detection is checked against the bundled static intel snapshot (CISA KEV + abuse.ch + MITRE references — `src/network_threat/data/intel_static.json`); a tag match uplifts severity one level (MEDIUM → HIGH → CRITICAL, capped). Suricata detections are never enriched (signature already carries its own intel).

Output: OCSF v1.3 Detection Finding (`class_uid 2004`, `types[0]="network_threat"`) wrapped per detection. Operators see beacons and DGA domains **pinned above** the per-severity sections (mirrors F.6 tamper-pin + D.3 critical-pin patterns).

## ADR-007 conformance

D.4 is the **seventh** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`). **Not** in the v1.3 always-on class — D.4 honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

LLM use: **not load-bearing** (contrast with D.7). Detectors are deterministic. The `LLMProvider` parameter on `agent.run` is plumbed but never called in v0.1 — keeps the contract surface stable when Phase 1c adds optional LLM narrative.

## Quick start

```bash
# 1. Run the local eval suite (10/10)
uv run network-threat eval packages/agents/network-threat/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner network_threat \
    --cases packages/agents/network-threat/eval/cases \
    --output /tmp/d4-eval-out.json

# 3. Run against an ExecutionContract — three optional feeds
uv run network-threat run \
    --contract path/to/contract.yaml \
    --suricata-feed /tmp/suricata-snapshot.json \
    --vpc-flow-feed /tmp/flow-snapshot.log.gz \
    --dns-feed /tmp/dns-snapshot.log
```

See [`runbooks/network_triage.md`](runbooks/network_triage.md) for the full operator workflow (staging the three feeds · interpreting the four artifacts · severity escalation rules · routing findings to D.7 Investigation + F.6 Audit · troubleshooting).

## Architecture

```
Suricata eve.json ────→ read_suricata_alerts ───┐
AWS VPC Flow Logs ────→ read_vpc_flow_logs ─────┤  INGEST  ── TaskGroup
DNS logs (BIND/R53) ──→ read_dns_logs ──────────┘     │
                                                       ▼
                                              ┌────────┴────────┐
                                              │ detect_port_scan│
                                              │ detect_beacon   │  PATTERN_DETECT
                                              │ detect_dga      │  (pure, no I/O)
                                              │ + Suricata lift │
                                              └────────┬────────┘
                                                       │
                                              enrich_with_intel  ENRICH
                                              (severity uplift)
                                                       │
                                                  dedup pass     SCORE
                                              (Detection.dedup_key)
                                                       │
                                              render_summary +   SUMMARIZE +
                                              build_finding ×N   HANDOFF
                                                       │
                                                       ▼
                                          findings.json + report.md
                                                + audit.jsonl
```

Six tool wrappers feed the orchestrator: three filesystem readers ([`tools/`](src/network_threat/tools/)) and three pure-function detectors ([`detectors/`](src/network_threat/detectors/)). Plus enrichment ([`enrichment.py`](src/network_threat/enrichment.py)), summarizer ([`summarizer.py`](src/network_threat/summarizer.py)), and the agent driver ([`agent.py`](src/network_threat/agent.py)).

## Output contract — the three artifacts

| File            | Format                                | Purpose                                                                                                             |
| --------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `findings.json` | `FindingsReport.model_dump_json()`    | Wire shape consumed by D.7 Investigation, fabric routing, Meta-Harness. OCSF 2004 array under `findings`.           |
| `report.md`     | Markdown                              | Operator summary — beacons + DGA pinned **above** per-severity sections; severity + finding-type breakdowns on top. |
| `audit.jsonl`   | `charter.audit.AuditEntry` JSON-lines | This run's own hash-chained audit log. F.6 `audit-agent query` reads it.                                            |

```python
# findings.json (OCSF 2004)
{
    "agent": "network_threat",
    "findings": [
        {
            "class_uid": 2004,
            "finding_info": {
                "uid": "NETWORK-BEACON-100005-001-periodic",
                "types": ["network_threat"],
                "product_uid": "beacon@0.1.0",
                ...
            },
            "severity_id": 5,  # CRITICAL
            "severity": "Critical",
            "affected_networks": [{"ip": "10.0.0.5", "traffic": {"dst_ip": "185.220.101.42", "dst_port": 443}, ...}],
            "evidences": [{
                "src_ip": "10.0.0.5", "dst_ip": "185.220.101.42", "dst_port": 443,
                "connection_count": 60, "period_seconds": 60.001,
                "coefficient_of_variation": 0.007, "confidence": 0.997,
                "intel": {"tags": ["known_bad", "tor_exit"], "matched_ip_cidr": "185.220.101.0/24"}
            }]
        }
    ]
}
```

## Tests

```bash
uv run pytest packages/agents/network-threat -q
```

231 tests; mypy strict clean across all 15 source files. **10/10 eval acceptance gate** via the eval-framework entry-point:

```bash
uv run eval-framework run --runner network_threat \
    --cases packages/agents/network-threat/eval/cases \
    --output /tmp/d4-eval-out.json
# → 10/10 passed (100.0%)
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). The substrate this agent consumes (`charter`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
