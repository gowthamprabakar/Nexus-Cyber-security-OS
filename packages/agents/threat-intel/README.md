# `nexus-threat-intel-agent`

Threat Intel Agent — **D.8**; **second of the 7 unbuilt agents** under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **twelfth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / **D.8**). Lifts platform coverage from siloed detection to threat-context correlation.

> **Bootstrap (Task 1) — 2026-05-21.** Package scaffold + pyproject + smoke tests only. No feed clients, no correlators, no driver yet. See [`docs/superpowers/plans/2026-05-21-d-8-threat-intel-v0-1.md`](../../../docs/superpowers/plans/2026-05-21-d-8-threat-intel-v0-1.md) for the full 16-task plan.

## Scope (v0.1)

3 public, no-auth feeds (offline-mode JSON snapshots staged by the operator):

- **NVD CVE JSON 2.0** (public domain).
- **CISA KEV catalog** (CC0).
- **MITRE ATT&CK STIX 2.1** (CC-BY-4.0 — attribution footer required in `report.md`).

3 sibling-workspace correlators (read-only):

- `correlate_cve_kev` against D.1 Vulnerability findings.
- `correlate_ioc_network` against D.4 Network Threat findings.
- `correlate_ioc_runtime` against D.3 Runtime Threat findings.

SemanticStore writes for IOC / CVE / TTP entities (single-tenant `semantic_store=None` opt-in default). OCSF v1.3 Detection Finding (`class_uid 2004`) re-exported from D.4 with `finding_info.types[0]="threat_intel"` discriminator. Deterministic (no LLM in loop).

## Deferred to D.8 v0.2 / v0.3 / v0.4 / v0.5+

- **v0.2:** live HTTP polling; MISP + STIX/TAXII; abuse.ch + VirusTotal.
- **v0.3:** active-campaign tracking; customer-specific correlation engine.
- **v0.4:** vertical-specific feeds (FS-ISAC / H-ISAC).
- **v0.5+:** predictive-exploitation-risk modeling; custom threat-actor attribution; commercial-feed credential management ADR.
- **Multi-tenant production** blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

Full version trajectory: [`docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md` §13](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md#13-d8-threat-intel).

## ADR-007 conformance

D.8 is the **12th** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`). **Not** in the v1.3 always-on class — D.8 honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

**Schema reuse (Q1).** D.8 re-exports D.4's `class_uid 2004 Detection Finding` schema verbatim (lands in Task 2) — `Severity`, `AffectedResource`, `build_finding`, `FindingsReport`. Adds `ThreatIntelFindingType` enum (4 correlator buckets) + `IocType` enum (5 IOC kinds) on top.

## Quick start

Package is currently at Bootstrap stage (Task 1). CLI + driver land in Tasks 12 / 14 / 15. To run the smoke tests:

```bash
uv run pytest packages/agents/threat-intel -q
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `network-threat`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
