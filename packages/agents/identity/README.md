# `nexus-identity`

Identity Agent — agent **#3 of 18** for Nexus Cyber OS. **Multi-cloud CIEM** (Cloud
Infrastructure Entitlement Management) — **v0.2 = Level 2**: live AWS IAM + live Azure
AD / Entra + basic SAML/OIDC federation forensics. **The canonical 3rd consumer of the
ADR-007 charter hoist** — this is the cycle where Patterns A (`CredentialResolver`),
D (live-eval lane gating) and E (partial-scan degradation) were hoisted into
[`nexus-charter`](../../charter/) and adopted here.

## What it does

Maps cloud principals to their effective permissions and emits OCSF v1.3 Detection
Findings (`class_uid 2004`). **Per-cloud coverage is measured separately, never
aggregated** (WI-I1).

**AWS IAM** (live via the hoisted `CredentialResolver`): users / roles / groups +
customer-managed policies + Access Analyzer. **Azure AD / Entra** (live via Microsoft
Graph): users + groups + service principals + managed identities. Five detection types:

- **OVERPRIVILEGE** — admin-equivalent grants (`*:*`, `iam:*`, service-wide wildcards).
- **DORMANT** — users / roles whose `last_used_at` is older than the threshold (default 90 days).
- **EXTERNAL_ACCESS** — cross-account or public access surfaced by AWS Access Analyzer.
- **MFA_GAP** — admin-capable IAM users without MFA enforced (signal supplied by the caller).
- **FEDERATION** — external-IdP SAML/OIDC trust relationships (IAM SAML/OIDC providers;
  Azure AD federated domains + tenant OIDC IdPs). Basic detection (Q5); deep chains → v0.3.

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

# 3. Run against a live AWS account (see runbooks/aws_iam_live_scan.md)
uv run identity-agent run \
    --contract path/to/contract.yaml \
    --profile dev-readonly \
    --analyzer-arn arn:aws:access-analyzer:us-east-1:111111111111:analyzer/nexus \
    --mfa-user alice --mfa-user bob \
    --dormant-threshold-days 90

# 4. Gated live end-to-end lanes (read-only; skip cleanly when unset)
AWS_PROFILE=dev NEXUS_LIVE_IDENTITY_AWS=1 \
    uv run pytest packages/agents/identity/tests/integration/test_agent_aws_e2e.py -v
NEXUS_LIVE_IDENTITY_AZURE=1 \
    uv run pytest packages/agents/identity/tests/integration -k azure -v
```

See the per-cloud runbooks: [`runbooks/aws_iam_live_scan.md`](runbooks/aws_iam_live_scan.md)
and [`runbooks/azure_ad_live_scan.md`](runbooks/azure_ad_live_scan.md).

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

## v0.2 deferred scope (→ v0.3, per ADR-017)

What v0.2 (Level 2) deliberately does **not** do — stated plainly so the boundary is
explicit:

- **GCP IAM CIEM** (Q4) — AWS + Azure only at v0.2.
- **Effective-permissions simulator + used-vs-granted** (Q7) — the IAM
  `SimulatePrincipalPolicy` wrapper exists and is tested, but per-principal simulation
  is the L3 residual. v0.2 admin detection is managed-policy-ARN-based.
- **Inline-policy admin detection** — v0.2 enumerates inline policy _names_ + the
  account's customer-managed policy _documents_; statement-level admin detection over
  them pairs with the simulator (v0.3).
- **Azure Conditional Access + PIM** (Q3); per-app workload identity federation
  (`federatedIdentityCredentials`) — tenant-level OIDC IdPs only at v0.2 (WI-I6).
- **Deep cross-cloud federation chains** (Okta → AWS → assume-role paths, Q5).
- **Multi-account / multi-tenant** (Q6) — single AWS account / single Azure tenant.
- **IAM `Condition` evaluation / SCPs / permission-boundary subtraction** in the driver.

## License

BSL 1.1 — agent-specific code per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). The runtime substrate (`nexus-charter`, `nexus-eval-framework`) ships under Apache 2.0.

## See also

- [D.2 plan](../../../docs/superpowers/plans/2026-05-11-d-2-identity-agent.md) — implementation plan (16 tasks).
- [Cloud Posture Agent](../cloud-posture/) — the F.3 reference template.
- [Vulnerability Agent](../vulnerability/) — the D.1 second-template validation.
- [`charter.llm_adapter`](../../charter/src/charter/llm_adapter.py) — shared LLM adapter (no per-agent `llm.py`).
- [D.2 v0.2 plan](../../../docs/superpowers/plans/2026-06-10-d-2-identity-v0-2.md) — the multi-cloud + charter-hoist cycle.
- Runbooks: [aws_iam_live_scan.md](runbooks/aws_iam_live_scan.md) · [azure_ad_live_scan.md](runbooks/azure_ad_live_scan.md).
