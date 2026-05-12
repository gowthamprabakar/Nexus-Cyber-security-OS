# Audit query — operator runbook

Owner: audit on-call · Audience: a compliance operator or SRE running an audit-chain query · Last reviewed: 2026-05-12.

This runbook is the **operator-facing workflow** for the Audit Agent. After F.5 ([memory_bootstrap.md](../../charter/runbooks/memory_bootstrap.md)) has the substrate up, this runbook covers running an actual audit query: collecting `audit.jsonl` sources, invoking `audit-agent query`, interpreting the result, and reacting to a chain tamper.

> **Status:** v0.1. Phase 1b introduces real-time streaming ingest (Kafka/NATS) + a built-in PagerDuty/Slack routing for chain breaks. Today the workflow is run-on-demand + the CLI exit code drives downstream automation.

---

## Prerequisites

- A running F.5 substrate (`charter.memory` alembic upgraded; see [`memory_bootstrap.md`](../../charter/runbooks/memory_bootstrap.md)).
- One or more `audit.jsonl` sources. Each Nexus agent writes its run's chain to `<workspace>/audit.jsonl` via `charter.audit.AuditLog`.
- This monorepo checkout with `uv sync` clean.
- For NL queries: an LLM provider configured via `NEXUS_LLM_*` env vars. Without one, the CLI falls back to structured-flag-only queries (no semantic difference; flag-driven flows still work).

---

## 1. Collect audit sources

In production, audit chains land under `/var/log/nexus/audit/<agent>/<delegation_id>.jsonl` (one chain per agent invocation). Two collection patterns:

### 1a. Single-source query

The simplest case — you have one chain file (e.g. a SOC 2 auditor handed it to you):

```bash
audit-agent query \
    --tenant 01HV0T0000000000000000TENA \
    --workspace /tmp/audit-query-ws \
    --source /path/to/audit-2026-05-01.jsonl \
    --format markdown
```

### 1b. Multi-source query

Ingest every chain file across an agent's runs for a window:

```bash
audit-agent query \
    --tenant 01HV0T0000000000000000TENA \
    --workspace /tmp/audit-query-ws \
    --source /var/log/nexus/audit/cloud_posture/01J7M*.jsonl \
    --source /var/log/nexus/audit/runtime_threat/01J7M*.jsonl \
    --since 2026-05-01 \
    --until 2026-05-31 \
    --format markdown
```

(The shell globs each `--source` before invocation; `audit-agent` itself takes one file per flag, repeated.)

---

## 2. Run the query

Three output formats are supported:

| Format               | Use when                                                               |
| -------------------- | ---------------------------------------------------------------------- |
| `markdown` (default) | Operator review — pinned tamper alerts above per-action sections.      |
| `json`               | Feed into another tool (Meta-Harness, BI dashboard, ticketing system). |
| `csv`                | Hand to an auditor for spreadsheet inspection.                         |

All five filter axes are honoured per format:

```bash
audit-agent query \
    --tenant 01HV0T0000000000000000TENA \
    --workspace /tmp/audit-query-ws \
    --source /path/to/audit.jsonl \
    --since 2026-05-15T00:00:00Z \
    --until 2026-05-15T23:59:59Z \
    --action episode_appended \
    --agent-id cloud_posture \
    --correlation-id 01J7M3X9Z1K8RPVQNH2T8DBHFZ \
    --format json
```

The `--workspace` flag is the scratch directory the CLI uses for the in-memory `audit_events` aiosqlite store. After the query returns, the workspace can be deleted — its only role is run isolation.

---

## 3. Read the markdown report

The default `markdown` output renders top-down:

```
# Audit summary — tenant <id>, <since> → <until>

## Chain integrity
Chain valid (<N> entries checked).            ← or break details

## Volume by action       ← sorted desc by count
## Volume by agent        ← sorted desc by count
## Tamper alerts pinned   ← present ONLY on chain break
## Per-action sections    ← sorted desc by section size
```

The tamper section, when present, sits **above** the per-action sections so an operator never has to scroll past noise to see a chain break.

---

## 4. Interpret exit codes

The CLI's exit code is the contract automation downstream cron jobs rely on:

| Exit code | Meaning                                                                                                                                                                                           |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **0**     | Clean query — every source's chain verified end-to-end. The result is trustworthy.                                                                                                                |
| **1**     | Tooling failure — bad contract YAML, unreachable source path, malformed CLI args, etc. Re-run after fixing the input.                                                                             |
| **2**     | **Chain tamper detected.** At least one source's hash chain broke verification. The result still rendered (you see what's there), but the chain itself is no longer trustworthy. **Investigate**. |

A cron job consumes exit 2 like this:

```bash
#!/usr/bin/env bash
set -uo pipefail

audit-agent query \
    --tenant $TENANT_ID \
    --workspace /tmp/audit-cron-ws \
    --source $LATEST_AUDIT_FILE \
    --format markdown \
    > /tmp/audit-report.md
ec=$?

if [ $ec -eq 2 ]; then
    notify_oncall "Audit chain tamper detected for tenant $TENANT_ID"
    upload_evidence /tmp/audit-report.md "$LATEST_AUDIT_FILE"
    exit 2
fi
exit $ec
```

---

## 5. Respond to a chain tamper

A `Chain BROKEN` report means the recomputed entry hash didn't match the stored one, or the previous-hash chain link didn't hold. **Do not** auto-correct the chain — the chain is the evidence; correcting it destroys the artifact you need for the investigation.

The triage path:

1. **Read the pinned break details** in the markdown report. The `broken_at_correlation_id` and `broken_at_action` identify the first event that failed verification. Earlier events (up to `entries_checked`) are still trustworthy.
2. **Locate the source file** via the breaking event's `source` field (e.g. `jsonl:/var/log/nexus/audit/cloud_posture/01J7M3X9....jsonl`).
3. **Compare against a backup.** If the source file is the canary, restoring from a known-good backup is the response — not editing the live file. Cloud-native logging (Cloud Logging / CloudWatch) is the operator's primary backup since these logs ship to immutable storage on emit.
4. **File a compliance-incident ticket.** Capture: tenant, breaking correlation_id, source path, the recomputed-vs-stored hash diff, and the timeline (when did the file last verify clean?).
5. **Do not delete the broken chain.** Quarantine the file. It's evidence.

What the Audit Agent does **not** do:

- **No auto-correction.** The chain is evidence; correcting it destroys what it's for.
- **No direct paging.** v0.1 surfaces breaks via CLI exit code only. Phase 1c adds PagerDuty/Slack routing.
- **No chain-check skip.** Always-on means always-on — there's no flag that turns chain verification off. If you don't want chain verification, you don't want the Audit Agent.

---

## 6. NL-query path (optional)

`audit-agent query` does not currently expose an `--nl-query` flag — that's plumbed through the agent driver's `run` path. The NL pipeline lives in [`audit.query_translator.translate_nl_query`](../src/audit/query_translator.py) and is exercised by eval case 010. Operators in v0.1 use structured flags.

Phase 1b adds `audit-agent query --nl "show me every episode appended for tenant X in the last 24 hours"` once the LLM-routing UX has been validated against more eval cases.

---

## 7. Multi-tenant guard rail

`audit-agent query` requires `--tenant` and stamps it onto every query against `audit_events`. Postgres RLS (from `0003_audit_events`) is the primary defence — even direct SQL against the table can only see the active tenant's rows after the `SET LOCAL app.tenant_id` that `MemoryService.session()` installs. The CLI's application filter is the secondary defence.

If you need to compare two tenants, run two separate queries. Cross-tenant queries are Phase 2 work and are gated behind a compliance-approval workflow.

---

## 8. Troubleshooting

| Symptom                                                           | Likely cause                                                                              | Fix                                                                                           |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `audit-agent query` exits 1 with `Source not found`               | --source path missing or unreadable.                                                      | Verify path; fix permissions; re-run.                                                         |
| Exit 2 but the source file looks intact                           | Chain was broken at write time (e.g. partial flush during a crash).                       | Compare with cloud-logging backup; replay the run if a backup is missing.                     |
| `--format json` output has `total: 0` but you expected events     | Filter combination is too narrow (likely --since/--until window).                         | Widen the window; remove --action / --agent-id; re-run.                                       |
| Markdown report's "Volume by action" is empty                     | No events matched the tenant + window. Check the contract's tenant_id matches the source. | Cross-check `audit.jsonl` source's emitting run with the operator's `--tenant`.               |
| `audit-agent run` exits without producing `report.md`             | Contract YAML invalid or workspace permissions wrong.                                     | `cat path/to/contract.yaml` to verify; check workspace is writable.                           |
| NL query returns "everything for tenant" no matter what was asked | LLM provider unavailable or returned non-JSON; fallback path engaged.                     | Set `NEXUS_LLM_*` env vars and re-run; or fall back to structured `--action`/`--since` flags. |

---

## Cross-references

- F.6 plan: [`docs/superpowers/plans/2026-05-12-f-6-audit-agent.md`](../../../docs/superpowers/plans/2026-05-12-f-6-audit-agent.md)
- F.5 bootstrap (prerequisite): [`packages/charter/runbooks/memory_bootstrap.md`](../../charter/runbooks/memory_bootstrap.md)
- ADR-007 (reference NLAH, v1.3 always-on amendment): [`docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md`](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)
- ADR-009 (memory architecture; F.6 audit_events table extends it): [`docs/_meta/decisions/ADR-009-memory-architecture.md`](../../../docs/_meta/decisions/ADR-009-memory-architecture.md)
