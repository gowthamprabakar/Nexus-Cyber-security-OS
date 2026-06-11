# `nexus-compliance-agent`

Compliance Agent — **D.6**; **third of the 7 unbuilt agents** shipped under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **thirteenth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / D.5 / D.8 / **D.6**). Maps sibling-agent findings (F.3 Cloud Posture + D.5 Data Security) to compliance-framework controls and emits framework-level compliance findings + a posture-summary report.

> **v0.1 shipped 2026-05-21.** 16 tasks, PRs #89-#104 merged. 225 tests passing. 10/10 eval cases pass. Q6 CIS Benchmarks® attribution + paraphrase posture verified at unit, render, and CLI layers. See [`docs/_meta/d-6-compliance-v0-1-verification-2026-05-21.md`](../../../docs/_meta/d-6-compliance-v0-1-verification-2026-05-21.md) for the closure record.

> **v0.2 — operator Cycle 9 (`__version__` 0.1.0 → 0.2.0, 2026-06-11).** The **first Group D consumer #2** (inherits the k8s-posture Cycle 8 pattern); compliance becomes the **4th OCSF 2003 emitter** (with F.3 / D.5 / k8s-posture). This cycle adds, keeping the offline `run()`/eval byte-identical (WI-C5): the **full CIS family** — CIS-AWS v3 + **CIS-Azure v2 + CIS-GCP v2 + CIS-K8s v1.8** control libraries (`control_libraries/` + readers); **PASS attestation** alongside FAIL (`build_pass_finding` + `attestation.py` — a PASS carries **positive evidence**, not just absence of FAIL, WI-C6); **multi-emitter consumption** (`consumption.py` — F.3 + D.5 + k8s-posture → evaluated/failing sets → per-framework roll-up); **continuous-monitoring INFRASTRUCTURE** (`continuous/` — scheduler + delta + heartbeat-coexistence); and **audit-ready evidence bundles** (`evidence/` — hash-chained entries + signed manifest + JSON/PDF-ready export). Single gated lane `NEXUS_LIVE_COMPLIANCE` (WI-C2/C7 multi-emitter e2e). Setup: [`runbooks/`](runbooks/); per-framework coverage (no aggregate, WI-C1) + the closure record under `docs/_meta/compliance-v0-2-*`.
>
> **Honest wiring (operator-confirmed 2026-06-11):** a control wires **only** to a source rule a sibling agent actually emits — the emitters expose ~7 (F.3 AWS) / 8 (D.5 Azure) / 10 (D.5 GCP) / 15 (k8s-posture) stable rules, so CIS-AWS is ~14/43 wired and the rest of the family is a representative wired subset. Broader coverage tracks the **emitters** expanding their rule catalogs, never compliance fabricating mappings (a drift-guard test enforces this). **Advisory only (WI-C11):** compliance emits + maps; it never enforces — A.1 Remediation owns enforcement. PCI-DSS / HIPAA / SOC2 / NIST / GDPR are Phase D.
>
> **Honest scope (WI-C3 / Path 1):** continuous mode is **INFRASTRUCTURE** at v0.2; wiring it into the agent's `run()` loop is the **Phase C consolidated retrofit** (after all 17 v0.2 cycles), NOT a v0.3 carry-forward. The offline `run()` stays the deterministic OCSF-emitting path (WI-C5).

## Scope (v0.1)

**1 framework** (bundled as paraphrased YAML; Q6 — CIS Securesuite licence restricts verbatim redistribution):

- **CIS AWS Foundations Benchmark v3.0** — 45 paraphrased controls covering IAM (15), Storage (10), Logging (6), Monitoring (6), Networking (5).

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

D.6 is the **13th** agent under the reference template, **9th** shipped natively against v1.2 (D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / D.5 / D.8 / **D.6**). Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader`). **Not** in the v1.3 always-on class — D.6 honours every budget axis. **Does not consume** the v1.4 candidate; single-driver per the agent spec.

**Schema reuse (Q1).** D.6 re-exports F.3's `class_uid 2003 Compliance Finding` schema verbatim — `Severity`, `AffectedResource`, `FindingsReport`, OCSF constants. Adds `ComplianceFramework` enum + `ControlLevel` enum + `compliance_finding_type(framework, control_id)` discriminator builder + `severity_for_level(level, required)` canonical table + D.6-specific `COMPLIANCE_FINDING_ID_RE` and `build_finding` on top. Downstream consumers (D.7, Meta-Harness) filter on `class_uid == 2003` first then on `finding_info.types[0] == "compliance_*"` to disambiguate D.6 emits from F.3 / D.5 / multi-cloud / k8s posture emits.

## Smoke runbook

### 1. Verify the bundled CIS library

```bash
uv run python -c "
import asyncio
from compliance.tools.cis_aws_benchmark import read_cis_aws_benchmark
print(f'Loaded {len(asyncio.run(read_cis_aws_benchmark()))} CIS controls.')
"
```

Expected: `Loaded 45 CIS controls.`

### 2. Run the agent against sibling-agent workspaces

```bash
uv run compliance run \
    --contract path/to/execution-contract.yaml \
    --cloud-posture-workspace path/to/f3-cloud-posture-run/ \
    --data-security-workspace path/to/d5-data-security-run/
```

Each sibling workspace must contain a `findings.json` produced by the corresponding agent (F.3 Cloud Posture, D.5 Data Security). The agent writes `findings.json` (OCSF 2003 array, one finding per failing CIS control) + `report.md` (markdown with Level-1 pinned + CIS attribution) to the contract's workspace and prints a one-line digest of severity + per-control counts.

**Skipped inputs are tolerated.** Either workspace flag may be omitted; the corresponding correlator silently emits zero findings. The **CIS Benchmarks® attribution footer + paraphrase declaration** is rendered in `report.md` even on empty runs (Q6 / WI-2 compliance).

### 3. Run the local eval suite

```bash
uv run compliance eval packages/agents/compliance/eval/cases
```

Expected output: `10/10 passed`. Exit code 1 on any failure with per-failure `FAIL <case_id>: <reason>` lines.

### 4. Run the unit test suite

```bash
uv run pytest packages/agents/compliance -q
```

Expected: **225 passed** in <2s.

## Architecture

Seven-stage pipeline:

```text
INGEST    -> ENRICH      -> CORRELATE     -> AGGREGATE    -> SCORE     -> SUMMARIZE  -> HANDOFF
(bundled    (build           (2 sibling       (per-control     (canonical    (markdown      (findings.json
 CIS YAML    control          correlators      PASS/FAIL        Level x       with Level-     + report.md
 via         index +          via TaskGroup)   roll-up;         required      1 pinned +      to charter
 charter)    optional                          FAIL-floor       severity      CIS attrib-     workspace)
             KG writes)                        on MEDIUM)       re-stamp)     ution footer)
```

| Stage        | Module                                                                    | Output                                                               |
| ------------ | ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| 1. INGEST    | `tools/cis_aws_benchmark.py`                                              | `tuple[CisControl, ...]`                                             |
| 2. ENRICH    | `correlators/control_index.build_control_index` + `kg_writer.py` (opt-in) | control index + optional SemanticStore writes                        |
| 3. CORRELATE | `correlators/{cloud_posture,data_security}_correlator.py`                 | `tuple[ComplianceFinding, ...]` (per-mapping emits)                  |
| 4. AGGREGATE | `aggregator.py`                                                           | per-control roll-up; arn-deduped resources; FAIL-only output in v0.1 |
| 5. SCORE     | `scorer.py`                                                               | canonical-severity re-stamped findings                               |
| 6. SUMMARIZE | `summarizer.py`                                                           | markdown with Level-1 pinned + CIS Benchmarks® attribution footer    |
| 7. HANDOFF   | `agent.py`                                                                | `findings.json` + `report.md` to charter workspace                   |

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `data-security-agent`, `eval-framework`) is Apache 2.0; the agent itself is BSL.

**Third-party framework attribution** (carried in every `report.md` per Q6):

- **CIS Benchmarks®** — © Center for Internet Security, Inc. — https://www.cisecurity.org/cis-benchmarks/

The shipped control library (`control_libraries/cis_aws_v3.yaml`) carries **paraphrased operator-facing summaries written in-house** from public CIS reference metadata (control IDs + level + applicability). **No verbatim CIS Securesuite text is reproduced.** Per Q6 / WI-2: the `report.md` attribution footer + Task 4's `test_no_securesuite_anchor_text_in_descriptions` test enforce this posture.
