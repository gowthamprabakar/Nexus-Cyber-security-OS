# Runbook — Cross-Agent Audit Aggregation (audit v0.2)

## Setup

1. Point F.6 at the audit sources in scope: charter `audit.jsonl` path(s), the F.5 episodes
   DB, and/or per-agent chain locations (the 10 closed-cycle agents).
2. Cross-tenant queries require the `admin` role (WI-F11) — single-tenant needs none.

## Run (gated live)

```bash
NEXUS_LIVE_AUDIT=1 uv run pytest \
  packages/agents/audit/tests/integration/test_audit_cross_agent_e2e.py -v
```

## Invariants

- **WI-F8** F.6 is read-only — `assert_audit_readonly` hard-blocks any chain mutation.
- **WI-F2/WI-F9** tamper is detected + categorized + ALWAYS alerted; chains are NEVER repaired.
- **WI-F10** F.6's single `BY_DESIGN_EXEMPT` tool-proxy entry is preserved — no new exemptions.
