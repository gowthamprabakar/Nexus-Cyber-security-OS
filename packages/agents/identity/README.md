# `nexus-identity`

Identity Agent — agent **#3 of 18** for Nexus Cyber OS. CIEM (Cloud Infrastructure Entitlement Management) for AWS. **Second consumer of [ADR-007 v1.1](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (the `charter.llm_adapter` hoist), twice-validating the post-amendment canon.

## What it does

Maps AWS principals (IAM users, roles, groups) to their effective permissions and emits OCSF v1.3 Detection Findings (`class_uid 2004`) across four detection types:

- **OVERPRIVILEGE** — admin-equivalent grants (`*:*`, `iam:*`, service-wide wildcards).
- **DORMANT** — users / roles whose `last_used_at` is older than the threshold (default 90 days).
- **EXTERNAL_ACCESS** — cross-account or public access surfaced by AWS Access Analyzer.
- **MFA_GAP** — admin-capable IAM users without MFA enforced (signal supplied by the caller; cloud-posture's helpers feed it in Phase 1c).

Every action runs through the [runtime charter](../../charter/) — execution contract, per-dimension budget envelope, tool whitelist, audit chain — so the agent cannot exceed its sanctioned scope.

## Quick start

```bash
# 1. Run the local eval suite (10/10 should pass)
uv run identity-agent eval packages/agents/identity/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner identity \
    --cases packages/agents/identity/eval/cases \
    --output /tmp/identity_suite

# 3. Run against a live AWS account (see runbooks/scan_aws_account.md)
uv run identity-agent run \
    --contract path/to/contract.yaml \
    --profile prod-readonly \
    --analyzer-arn arn:aws:access-analyzer:us-east-1:111111111111:analyzer/nexus \
    --mfa-user alice --mfa-user bob \
    --dormant-threshold-days 90
```

## Inputs

A signed `ExecutionContract` (YAML) — schema defined by [`nexus-charter`](../../charter/). Required: budget envelope, permitted-tools whitelist (the three IAM/Access-Analyzer tools listed below), workspace + persistent_root, completion_condition, ULID `delegation_id`.

CLI flags supply the operational context: AWS profile/region, Access Analyzer ARN (optional; skipped when omitted), MFA-enabled user names (frozenset), dormant threshold.

## Outputs

Three files in the charter-managed workspace:

| File            | Shape                                                                                                         | Purpose                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `findings.json` | `FindingsReport` ([schemas.py](src/identity/schemas.py)) — OCSF v1.3 Detection Finding dicts (2004)           | Wire format on the future `findings.>` fabric subject |
| `summary.md`    | Markdown digest — severity breakdown, finding-type breakdown, high-risk-principals pin, per-severity sections | Human-readable for SREs / auditors                    |
| `audit.jsonl`   | Append-only hash chain of every charter event                                                                 | Verified by `uv run charter audit verify`             |

## Architecture

```
ExecutionContract (YAML)
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Charter context manager                                      │
│   - workspace setup                                          │
│   - per-dimension budget envelope                            │
│   - tool whitelist (only what the contract permits)          │
│   - hash-chained audit at audit.jsonl                        │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Async tool wrappers (per ADR-005)                            │
│   - aws_iam_list_identities (boto3 → asyncio.to_thread)      │
│   - aws_iam_simulate_principal_policy (boto3 → thread;       │
│     wrapper exists, unused in v0.1 deterministic flow)       │
│   - aws_access_analyzer_findings (boto3 → thread)            │
│   - permission_paths.resolve_effective_grants (pure Python)  │
└──────────────────────────────────────────────────────────────┘
    │ concurrent IAM listing + Access Analyzer fetch
    │ via asyncio.TaskGroup
    ▼
┌──────────────────────────────────────────────────────────────┐
│ Normalizer — IdentityListing + EffectiveGrants + AA findings │
│     + MFA signal → OCSF Detection Findings (2004)            │
│   Four families: overprivilege / dormant / external_access / │
│   mfa_gap.                                                   │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
findings.json + summary.md + audit.jsonl
    │
    ▼
eval suite (10/10 cases via the F.2 framework)
```

## Public surface

```python
from identity.agent import run
from identity.schemas import (
    Severity,
    FindingType,
    AffectedPrincipal,
    IdentityFinding,
    FindingsReport,
    build_finding,
    short_principal_id,
)
from identity.tools.aws_iam import (
    aws_iam_list_identities,
    aws_iam_simulate_principal_policy,
    IamUser, IamRole, IamGroup, IdentityListing,
    SimulationDecision, IamListingError,
)
from identity.tools.aws_access_analyzer import (
    aws_access_analyzer_findings,
    AccessAnalyzerFinding, AccessAnalyzerError,
)
from identity.tools.permission_paths import (
    resolve_effective_grants,
    EffectiveGrant,
    grants_by_principal,
    is_admin_action,
    find_admin_principals,
)
from identity.normalizer import normalize_to_findings
from identity.summarizer import render_summary
from identity.eval_runner import IdentityEvalRunner
from identity.nlah_loader import load_system_prompt, default_nlah_dir

# ADR-007 v1.1: no per-agent llm.py — consume the hoisted adapter.
from charter.llm_adapter import LLMConfig, make_provider, config_from_env
```

Registered via `[project.entry-points."nexus_eval_runners"]` so the framework CLI can resolve `--runner identity` without import gymnastics.

## ADR-007 v1.1 conformance addendum

D.2 is the **second consumer of the post-amendment canon**. Per-task verdicts:

| ADR-007 pattern                                        | Task    | Verdict                                                                |
| ------------------------------------------------------ | ------- | ---------------------------------------------------------------------- |
| Schema-as-typing-layer (OCSF wire format)              | 2       | ✅ generalizes (`class_uid 2004` Detection Finding)                    |
| Async-by-default tool wrappers (boto3 → `to_thread`)   | 3, 4, 5 | ✅ generalizes                                                         |
| HTTP-wrapper convention                                | —       | n/a — Identity is boto3-only at the tool layer                         |
| Concurrent `asyncio.TaskGroup` enrichment              | 11      | ✅ generalizes (IAM listing + Access Analyzer fetch run in parallel)   |
| Markdown summarizer (top-down severity)                | 8       | ✅ generalizes; one delta — "High-risk principals" section pinned      |
| NLAH layout (README + tools.md + examples/)            | 9       | ✅ generalizes — **hoist candidate flagged for `charter.nlah_loader`** |
| LLM adapter via `charter.llm_adapter` (post-amendment) | 10      | ✅ **twice-validated** — anti-pattern guard test added                 |
| Charter context + `agent.run` signature shape          | 11      | ✅ generalizes                                                         |
| Eval-runner via entry-point group                      | 13      | ✅ generalizes (10/10 acceptance)                                      |
| CLI subcommand pattern (`eval` + `run`)                | 14      | ✅ generalizes                                                         |

**Follow-up flagged by D.2:** the NLAH loader (Task 9) is now materially identical across three agents — cloud-posture, vulnerability, identity. Hoist candidate for `charter.nlah_loader`. Surfaced in D.2 Task 16's verification record so it lands as ADR-007 v1.2 (or as a non-amendment refactor) before D.3.

## Phase 1 caps (deferred)

- **IAM `Condition` evaluation** — the resolver flattens decisions; condition keys are evidence only.
- **SCPs (Service Control Policies)** — single-account scope in v0.1.
- **Inline-policy admin detection** — v0.1 derives admin grants from attached managed policies. Inline policies require the simulator path (Phase 2).
- **Permission-boundary subtraction in v0.1 driver** — the simulator wrapper handles boundaries (it's tested), but the v0.1 driver doesn't invoke per-principal simulation.
- **Azure AD / Microsoft Entra, GCP IAM, SaaS IdPs** — Phase 2 multi-cloud / Phase 1c SSPM territory.

## License

BSL 1.1 — agent-specific code per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). The runtime substrate (`nexus-charter`, `nexus-eval-framework`) ships under Apache 2.0.

## See also

- [D.2 plan](../../../docs/superpowers/plans/2026-05-11-d-2-identity-agent.md) — implementation plan (16 tasks).
- [Cloud Posture Agent](../cloud-posture/) — the F.3 reference template.
- [Vulnerability Agent](../vulnerability/) — the D.1 second-template validation.
- [`charter.llm_adapter`](../../charter/src/charter/llm_adapter.py) — shared LLM adapter (no per-agent `llm.py`).
- Runbook: [scan_aws_account.md](runbooks/scan_aws_account.md).
