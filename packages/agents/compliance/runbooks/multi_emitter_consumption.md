# Runbook — Live Multi-Emitter Compliance Consumption (compliance v0.2)

compliance is a **consumer**: it reads sibling agents' OCSF 2003 findings and maps them to
CIS-family controls, emitting PASS + FAIL findings + an audit-ready evidence bundle.

## Setup

1. Run the emitters whose frameworks you want graded and collect their OCSF 2003 reports:
   - **CIS-AWS** ← F.3 cloud-posture (`cloud_posture`)
   - **CIS-Azure / CIS-GCP** ← D.5 multi-cloud-posture (`multi_cloud_posture`)
   - **CIS-K8s** ← k8s-posture (`k8s_posture`)
2. Make the reports available to compliance (workspace inputs).

## Run (gated live)

```bash
NEXUS_LIVE_COMPLIANCE=1 uv run pytest \
  packages/agents/compliance/tests/integration/test_compliance_multi_emitter_e2e.py -v
```

## What it produces

- Per-control PASS / FAIL / not-evaluated classification, rolled up per framework
  (PASS_count / FAIL_count / coverage_pct).
- **PASS attestation** with **positive evidence** (the evaluated rules), not just absence of
  FAIL (WI-C6) — a control is PASS-attested only if its mapped rules were evaluated.
- An audit-ready **evidence bundle** (one hash-chained entry per control) sealed by a
  **signed manifest** (v0.2 placeholder signer; F.6 audit signer slots in, WI-C9), exportable
  as JSON + a PDF-ready Markdown report.

## Notes

- **Advisory only** (WI-C11): compliance emits + maps; it never enforces or remediates — A.1
  Remediation owns enforcement.
- Continuous mode is INFRASTRUCTURE (scheduler + delta); wiring it into the run() loop is the
  Phase C consolidated retrofit (Q4/WI-C4), not v0.2.
- Wiring is honest: a control maps only to a rule an emitter actually emits (no fabricated
  coverage). See the per-framework coverage docs.
