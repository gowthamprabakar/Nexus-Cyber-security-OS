# ADR-017 — v0.2 (and beyond) cycle quality gate

- **Status:** **proposed**
- **Date:** 2026-06-10
- **Authors:** AI/Agent Eng
- **Stakeholders:** every cycle plan author; every PR reviewer; the cycle verification-record author; the operator (who approves cycle closure)
- **Cycle:** NLAH Framework Full Backfill — Milestone 2, Task 8
- **Builds on:** [ADR-007 v1.7](ADR-007-cloud-posture-as-reference-agent.md) (the compliance rubric), [ADR-011](ADR-011-pr-flow-and-branch-protection-discipline.md) (PR-flow discipline), [ADR-016](ADR-016-tool-proxy-hard-boundary.md) (the hard tool boundary)

## Context

The [NLAH framework audit (#316)](../nlah-framework-audit-2026-06-09.md) found finding **S-4**: every
v0.2 cycle (F.3, D.5, D.1) shipped **code + eval suites but left the NLAH describing the prior
version**. Concretely, two agents' NLAHs still listed now-shipped capabilities as out-of-scope:

- `multi-cloud-posture` (D.5 v0.2 shipped **live Azure + GCP**) — NLAH still said "v0.1 is offline-only;
  out of scope (v0.1): live SDK calls."
- `vulnerability` (D.1 v0.2 shipped **live ECR/ACR/GCR registry scanning**) — NLAH still said "out of
  scope (v0.1): private-registry auth across providers."

All four v0.2 agents also still carried `v0.1` version labels in the NLAH header. This is **drift**: the
natural-language harness — the artifact an operator and the agent itself reason from — diverged from the
running code. The audit warned that "every cycle we ship without NLAH discipline makes the gap worse."

The Full Backfill cycle closes the _existing_ drift in M3. This ADR stops it **recurring**: it turns the
end-of-cycle NLAH check from "something a diligent author remembers" into a **required gate** the cycle
cannot close without.

ADR-011 already requires a verification record per cycle and SAFETY-CRITICAL/LOW-RISK labelling per PR.
ADR-007 v1.7 defines the _steady-state_ per-agent compliance bar. Neither captures the _delta_ discipline
for a cycle that **extends an already-compliant agent** — which is exactly where S-4 happened.

## Decision

**No v0.2+ cycle may close until its verification record affirms the NLAH-delta gate below.** The gate is
a short, objective checklist appended to every cycle's verification record (the same document ADR-011
already requires). The cycle's closure PR is not approvable until each item is checked or marked N/A with
a one-line reason.

### The NLAH-delta gate

For each agent the cycle touched, confirm:

1. **Scope statements current.** No "out of scope (v0.x)" / "v0.x is offline-only" / "deferred" line in
   `nlah/README.md` describes a capability this cycle **shipped**. (The S-4 check, stated directly.)
2. **Version label bumped.** The NLAH header / version marker matches the agent's new `pyproject.toml`
   version. (No `v0.1` label on a `0.2.0` agent.)
3. **`tools.md` accurate.** Every tool the cycle added is listed; gated tools are labelled as dispatched
   via `ctx.call_tool`; no false "routes through the charter" claim; reserved/unwired tools marked.
4. **New tools registered + gated.** Any new side-effecting/external/stateful tool is registered in
   `build_registry()` and invoked only via `ctx.call_tool` (passes `test_tool_import_guard.py`); new
   pure helpers are _not_ registered. (Inherits ADR-016 item 16.)
5. **Self-evolution thresholds updated.** If the cycle changed detection breadth or added capabilities,
   the Layer-4 numeric thresholds in the NLAH reflect the new surface.
6. **Pattern declaration updated.** If the cycle added a control-flow pattern (e.g. a new parallel stage),
   the Layer-5 declaration is updated to match.
7. **Regression sweep includes an NLAH-consistency check.** The cycle's cross-agent regression evidence
   explicitly states the touched agents still satisfy the ADR-007 v1.7 checklist (not just that tests
   pass).

### How it is enforced

- **Mechanical backstop (preferred where cheap).** Items 1–2 and 4 are partly machine-checkable and
  SHOULD be wired as tests over time: e.g. an assertion that no NLAH `README.md` contains an
  "out of scope (vN)" line for a version ≤ the agent's current version, and that the NLAH version marker
  equals `pyproject` version. ADR-016's import guard already enforces item 4's gating half. Until a given
  check is automated, it is a **reviewer-confirmed** line in the verification record.
- **Process backstop (always).** The verification-record template gains an "NLAH-delta gate" section with
  these seven items. The cycle's closure PR (the ADR-011 verification-record PR) carries them filled in.
  A reviewer who finds an unchecked item that should be checked blocks closure.

## Consequences

**Positive**

- S-4 cannot silently recur: a cycle that ships a capability but not its NLAH update fails the gate.
- The NLAH stays a faithful description of the running agent — which is what both operators and the
  agents' own self-prompting depend on.
- The gate is cheap: seven yes/no items on a document the cycle already produces.

**Negative / costs**

- A small, real tax at cycle close (minutes per touched agent). This is the point — the S-4 tax was paid
  later, at audit time, across the whole fleet at once; this front-loads a fraction of it per cycle.
- Some items are reviewer-judgment until automated; the mechanical backstops should be added opportunistically.

## Alternatives considered

1. **Rely on ADR-007 v1.7 alone.** Rejected: v1.7 is the steady-state per-agent bar; it doesn't force a
   _delta_ re-check when a cycle extends an already-A agent — which is exactly the S-4 gap.
2. **Pure automation, no checklist.** Rejected for now: items 5–7 (threshold/pattern/consistency) need
   judgment a static check can't fully make. Automate the mechanical ones (1, 2, 4) incrementally; keep
   the checklist as the always-present backstop.
3. **Do nothing; fix drift each audit.** Rejected: that is the status quo the audit condemned — drift
   compounds and is paid in a large, late batch.

## References

- [NLAH framework audit (#316)](../nlah-framework-audit-2026-06-09.md) — finding S-4 (v0.2 NLAH drift)
- [ADR-007 v1.7](ADR-007-cloud-posture-as-reference-agent.md) — the steady-state per-agent compliance rubric this gate guards
- [ADR-011](ADR-011-pr-flow-and-branch-protection-discipline.md) — the verification-record + PR-flow discipline this gate plugs into
- [ADR-016](ADR-016-tool-proxy-hard-boundary.md) — the hard tool boundary (gate item 4)
- [Agent spec §0](../../agents/agent_specification_with_harness.md#section-0--as-built-convention-vs-original-spec) — as-built reconciliation
