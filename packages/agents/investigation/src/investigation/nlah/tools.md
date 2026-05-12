# Tools reference

Every tool below is async (per [ADR-005](../../../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md)) unless explicitly marked synchronous. Permissions and budget go through the runtime charter. D.7 is **NOT** in the v1.3 always-on class — every budget axis raises BudgetExhausted on overflow (extended caps: 10-minute wall clock, 30 LLM calls, 60000 tokens, 4 sub-agents).

## `audit_trail_query`

Pull cross-agent action history from F.6's `AuditStore`.

**Signature:** `await audit_trail_query(*, audit_store, tenant_id, since, until, action=None, agent_id=None, correlation_id=None, limit=500)`

**Output:** `tuple[AuditEvent, ...]` ordered by `(emitted_at, audit_event_id)` ascending. Empty window → `()`.

**Notes:** 500-event cap by default to bound memory during sub-agent fan-out. Page via multiple windowed queries for deep investigations.

## `memory_neighbors_walk`

BFS over F.5's `SemanticStore` knowledge graph. Use when an audit event names an entity (host, principal, finding) and you need its neighbors.

**Signature:** `await memory_neighbors_walk(*, semantic_store, tenant_id, entity_id, depth, edge_types=None)`

**Output:** `tuple[EntityRow, ...]` excluding the seed entity itself. Unknown seed → `()`.

**Notes:** Depth capped at `MAX_TRAVERSAL_DEPTH = 3`. Out-of-range raises `ValueError`.

## `find_related_findings`

Read `findings.json` from sibling-agent workspaces (operator-pinned).

**Signature:** `await find_related_findings(*, sibling_workspaces)`

**Output:** `tuple[RelatedFinding, ...]` carrying `source_agent`, `source_run_id`, `class_uid`, `payload`.

**Notes:** Forgiving on every failure mode — missing workspace / missing findings.json / malformed JSON → that sibling contributes zero RelatedFindings but doesn't poison the others.

## `extract_iocs`

Regex + heuristic IOC extraction. Synchronous (pure function).

**Signature:** `extract_iocs(content)` where `content` is `str | dict | list | tuple | nested`.

**Output:** `tuple[IocItem, ...]` — 9 types (ipv4, ipv6, domain, url, sha256, sha1, md5, email, cve), deduplicated by first appearance.

**Notes:** URL → suppresses nested domain emission; hash-length discrimination (33-char hex drops, not misclassified); CVE strict uppercase; loopback/zero IPv4 filtered.

## `map_to_mitre`

MITRE ATT&CK v14.x heuristic mapper. Synchronous.

**Signature:** `map_to_mitre(evidence)` where `evidence` is `str | dict | list | nested`.

**Output:** `tuple[MitreTechnique, ...]` ranked by keyword-hit count descending, then technique_id ascending. Empty / unmatched → `()`.

**Notes:** Bundled JSON table covers 10 techniques aligned with the five shipped Nexus agents' evidence shapes. No T0000 fallback — empty result is itself a signal.

## `SubAgentOrchestrator.spawn_batch`

Orchestrator-Workers primitive (Q2 resolution; ADR-007 v1.4 candidate). The only way for the agent driver to fan out sub-investigations.

**Signature:** `await orchestrator.spawn_batch(*, parent_depth, scopes, worker)`

**Output:** `tuple[SubResult, ...]` with `sub_id` / `kind` / `depth` / `scope` / `result` per scope.

**Notes:** Allowlist-enforced (only `investigation` may construct an orchestrator). Depth cap 3, parallel cap 5 — over-cap raises before any worker fires.

## `reconstruct_timeline`

Deterministic event merger. Synchronous.

**Signature:** `reconstruct_timeline(*, audit_events, related_findings, extra_events)`

**Output:** `Timeline` pydantic model. Auto-sorts ascending by `emitted_at`.

**Notes:** Forgiving — findings without parseable `time` field drop with a logged warning. Findings without `finding_info.uid` also drop (couldn't reference them from the report).

## `synthesize_report`

LLM-driven hypothesis generation via `charter.llm_adapter`. **Load-bearing** in D.7 — the only agent so far where LLM use is critical, not a UX nicety.

**Signature:** `await synthesize_report(*, llm_provider, audit_events, related_findings, timeline)`

**Output:** `tuple[Hypothesis, ...]` — each carries `evidence_refs` validated against the collected event set.

**Notes:** LLM unavailable falls back to deterministic "evidence enumeration" — one hypothesis per finding, confidence 0.5, statement = finding title. Hallucinated `evidence_refs` (those that don't resolve against the collected set) drop with a warning. Never lets fabricated evidence into the report.
