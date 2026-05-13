# Network Threat Agent — Tools Reference

Eight tools, grouped by stage. Each is async-safe (per ADR-005) so the agent driver can fan them out via `asyncio.TaskGroup` when appropriate.

## Stage 1: INGEST (three feeds, concurrent)

### `read_suricata_alerts(*, path: Path) -> tuple[SuricataAlert, ...]`

Async ndjson parser over a Suricata `eve.json` file. Only `event_type = "alert"` records are parsed; `dns` / `flow` / `http` / `tls` / `fileinfo` are dropped (routed to their typed readers).

- Handles both `Z` and `+0000` (no-colon) ISO-8601 timestamps.
- Severity parsed from `alert.severity` (1=HIGH, 2=MEDIUM, 3=LOW per Suricata convention).
- Preserves `flow_id`, `tx_id`, `community_id`, `alert.action` under `SuricataAlert.unmapped`.
- Forgiving — malformed JSON / missing fields / invalid severity are dropped without raising.

### `read_vpc_flow_logs(*, path: Path) -> tuple[FlowRecord, ...]`

Async AWS VPC Flow Logs reader. v2 / v3 / v4 / v5 superset; header-driven field map if a `version`-bearing tokens line tops the file, otherwise v2 default 14-field layout.

- Plaintext + gzipped both supported (magic-bytes detection at `\x1f\x8b`).
- `-` collapses to 0 for numeric fields; unknown `action` collapses to `NODATA`.
- Trailing extras preserved under `unmapped.extra_<i>`.

### `read_dns_logs(*, path: Path) -> tuple[DnsEvent, ...]`

Async DNS log reader. Auto-dispatches between BIND `named` query log (text) and AWS Route 53 Resolver Query Logs (ndjson) based on first-non-blank-line peek.

- `query_name` normalised to lowercase, trailing dot stripped.
- Route 53 `answers` collected from `{"Rdata": ..., "Type": ..., "Class": ...}` shape.
- BIND `%f` parses 1–6 digit subseconds; tz stamped UTC.

## Stage 2: PATTERN_DETECT (three pure-function detectors)

### `detect_port_scan(flow_records: Sequence[FlowRecord], *, min_distinct_ports: int = 50, window_seconds: int = 60) -> tuple[Detection, ...]`

Connection-rate heuristic. Sliding-window scan per source IP; emits one Detection per (src, threshold-crossing window). Severity escalates: ≥50 → MEDIUM, ≥100 → HIGH, ≥200 → CRITICAL. ACCEPT-only; loopback / link-local / unspecified src filtered.

Evidence: `src_ip`, `distinct_ports`, `window_seconds`, `ports_sampled[:10]`, `window_start`, `window_end`.

### `detect_beacon(flow_records: Sequence[FlowRecord], *, min_count: int = 5, max_cov: float = 0.30, min_period_seconds: float = 1.0) -> tuple[Detection, ...]`

Periodicity analysis grouped by `(src_ip, dst_ip, dst_port)`. Emits one Detection per pair with CoV ≤ max and count ≥ min. Severity: count≥50 + CoV≤0.10 → CRITICAL; count≥20 + CoV≤0.20 → HIGH; otherwise MEDIUM.

Evidence: `src_ip`, `dst_ip`, `dst_port`, `connection_count`, `period_seconds`, `variance_seconds`, `coefficient_of_variation`, `confidence` ∈ [0, 1], `first_seen`, `last_seen`.

### `detect_dga(dns_events: Sequence[DnsEvent], *, min_entropy: float = 3.5, max_bigram_score: float = 0.30, min_label_length: int = 7) -> tuple[Detection, ...]`

Shannon entropy + bigram heuristic on the second-level DNS label. Emits one Detection per unique `(src_ip, query_name)`. Severity HIGH at entropy ≥ 4.0 AND bigram ≤ 0.05; otherwise MEDIUM. Bundled CDN/cloud suffix allowlist skips trusted parents.

Evidence: `query_name`, `second_level_label`, `entropy`, `bigram_score`, `src_ip`, `query_type`.

## Stage 3: ENRICH

### `enrich_with_intel(detections: Sequence[Detection]) -> tuple[Detection, ...]`

Annotates each detection with bundled-static-intel tags (CISA KEV + abuse.ch + MITRE references — snapshot date in `data/intel_static.json`). Match rules:

- DGA: `query_name` ↔ `known_bad_domains` (suffix match).
- Beacon: `dst_ip` ↔ `known_bad_ip_cidrs` + `tor_exit_node_cidrs`.
- Port-scan: `src_ip` ↔ same two CIDR sets.
- Suricata: no enrichment (the signature carries its own intel).

When a tag matches, severity is uplifted one level (MEDIUM → HIGH → CRITICAL). The annotation lands at `evidence['intel']` with `tags`, `matched_ip_cidr`, `matched_domain_suffix`.

## Stage 5: SUMMARIZE

### `summarize_to_markdown(report: FindingsReport) -> str`

Renders the OCSF findings report as a markdown document with beacons + DGA pinned above per-finding-type sections. Mirrors F.6 tamper-alert pin pattern.

(Lands in Task 11.)
