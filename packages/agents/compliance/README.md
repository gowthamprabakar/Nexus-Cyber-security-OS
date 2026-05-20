# `nexus-compliance-agent`

Compliance Agent — **D.6**; **third of the 7 unbuilt agents** under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **thirteenth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / **D.6**). Maps sibling-agent findings to compliance-framework controls and emits framework-level compliance findings + a posture-summary report.

> **Bootstrap (Task 1) — 2026-05-21.** Package scaffold + pyproject + smoke tests only. No framework loader, no correlators, no driver yet. See [`docs/superpowers/plans/2026-05-21-d-6-compliance-v0-1.md`](../../../docs/superpowers/plans/2026-05-21-d-6-compliance-v0-1.md) for the full 16-task plan.

## Scope (v0.1)

**1 framework** (bundled as paraphrased YAML; Q6 — CIS Securesuite licence restricts verbatim redistribution):

- **CIS AWS Foundations Benchmark v3.0** (~50 paraphrased controls).

**2 sibling-workspace correlators** (read-only, operator-pinned via flags):

- `correlate_cloud_posture` against F.3 Cloud Posture findings.
- `correlate_data_security` against D.5 Data Security findings.

Per-control PASS/FAIL roll-up: one `ComplianceFinding` per `(control, status-change)` tuple; FAIL if any contributing source-finding has severity ≥ MEDIUM. PASS controls omitted from v0.1 output (added in v0.2 for attestation export). OCSF v1.3 Compliance Finding (`class_uid 2003`) re-exported from F.3 with `finding_info.types[0]="compliance_cis_aws_v3_<control_id>"` discriminator. Deterministic (no LLM in loop).

## Deferred to D.6 v0.2 / v0.3 / v0.4 / v0.5+

- **v0.2:** SOC2, PCI-DSS v4.0, HIPAA Security Rule, NIST 800-53 Rev. 5; PASS-finding emission for attestation export; F.6 audit-chain live read; periodic posture deltas via `findings.>` fabric-event subscription.
- **v0.3:** vendor-specific compliance dashboards; auditor-export PDF.
- **v0.4+:** customer-pinned framework subsets; control-level remediation playbooks.
- **Multi-tenant production** blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

Full version trajectory: [`docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md`](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md).

## ADR-007 conformance

D.6 is the **13th** agent under the reference template, **9th** shipped natively against v1.2. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`, lands in Task 12). **Not** in the v1.3 always-on class — D.6 honours every budget axis. **Does not consume** the v1.4 candidate; single-driver per the agent spec.

**Schema reuse (Q1).** D.6 re-exports F.3's `class_uid 2003 Compliance Finding` schema verbatim (lands in Task 2) — `Severity`, `AffectedResource`, `build_finding`, `FindingsReport`. Adds `ComplianceFindingType` (one per CIS control) + `ControlMapping` (CIS Level → Severity table) on top.

## Quick start

Package is currently at Bootstrap stage (Task 1). CLI + driver land in Tasks 11 / 13 / 14. To run the smoke tests:

```bash
uv run pytest packages/agents/compliance -q
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `data-security`, `eval-framework`) is Apache 2.0; the agent itself is BSL.

**Third-party framework attribution** (carried in every `report.md` per Q6; full text lands with the summarizer in Task 10):

- **CIS Benchmarks®** — © Center for Internet Security — https://www.cisecurity.org/cis-benchmarks/
