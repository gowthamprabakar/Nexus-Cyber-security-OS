# D.2 — Identity Agent (CIEM) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Identity Agent** (#3 of 18) — Cloud Infrastructure Entitlement Management (CIEM). Maps AWS principals (IAM users, roles, groups, federated identities) to their effective permissions, surfaces overprivilege, dormant identities, and risky permission paths. Normalizes findings to OCSF v1.3 Identity / Entitlement (`class_uid 3001`-class — see Task 2 for the precise selection), wraps them with the standard `NexusEnvelope`, and emits the same shape every other Track-D agent emits. Lives at `packages/agents/identity/`.

**Strategic role.** D.2 is the **second consumer of ADR-007 v1.1** (post-amendment). The amendment hoisted `llm.py` into `charter.llm_adapter`; this plan tests whether the hoist is the right level of abstraction by importing the adapter directly without recreating it. If the hoist holds, ADR-007 v1.1 is twice-validated; if it doesn't, we surface another amendment before D.3. **No new architectural decisions are expected** — the canon is locked.

**Architecture:** Same shape as F.3 / D.1. The capability swap is CSPM/Vulnerability → Identity:

```
ExecutionContract (YAML)
    │
    ▼
┌─────────────────────────────────────────────┐
│ Charter context manager (per F.1 / ADR-002) │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│ Async tool wrappers (per ADR-005)           │
│   - aws_iam_list_identities (boto3 → thread) │
│   - aws_iam_simulate_principal_policy        │
│   - aws_access_analyzer_findings             │
│   - permission_path_resolver (custom)        │
│   - dormant_identity_detector (custom)       │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│ OCSF v1.3 Identity / Entitlement Finding    │
│   wrapped with NexusEnvelope (per ADR-004)  │
└─────────────────────────────────────────────┘
    │
    ▼
findings.json + summary.md + audit.jsonl
    │
    ▼
eval suite (10/10 cases via the F.2 framework)
```

**Tech stack:** Python 3.12 · BSL 1.1 · pydantic 2.9 · boto3 (sync, threaded per ADR-005) · `nexus-charter` · `nexus-shared` · `nexus-eval-framework` (workspace deps). **No new HTTP clients** — Identity is boto3-only at the tool layer; charter.llm_adapter handles LLM provider selection per ADR-007 v1.1.

**Depends on:**

- F.1 (charter), F.2 (eval framework), ADR-007 v1.1 (post-LLM-adapter-hoist).
- The IAM tools in `cloud-posture/tools/aws_iam.py` (`list_users_without_mfa`, `list_admin_policies`) — D.2 either re-uses them via cross-package import or re-implements the underlying boto3 calls. Decision in Task 5.

**Defers (Phase 2+):**

- Azure Active Directory / Microsoft Entra integration (Phase 2 multi-cloud).
- GCP IAM mapping (deferred to Phase 2).
- Cross-account permission graphs (Cartography integration — Phase 1b D.7 Investigation Agent uses Cartography for the broader knowledge graph).
- Just-in-time access recommendations (Phase 1c after Tier-2 remediation lands).
- SaaS identity (Okta, AzureAD, Google Workspace) — D.10 SSPM territory.

**Reference template:** [F.3 Cloud Posture](2026-05-08-f-3-cloud-posture-reference-nlah.md) + [D.1 Vulnerability Agent](2026-05-10-d-1-vulnerability-agent.md). Don't re-derive what's already there. Both prior agents are valid templates.

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status     | Commit    | Notes                                                                                                            |
| ---- | ---------- | --------- | ---------------------------------------------------------------------------------------------------------------- |
| 1    | ✅ done    | `aa0f687` | Bootstrap `packages/agents/identity/` (pyproject, BSL, py.typed, README stub); `charter.llm_adapter` import test |
| 2    | ✅ done    | `9d4fbb5` | OCSF v1.3 Detection Finding schema (`class_uid 2004`) + 5-bucket FindingType enum; 17 tests; pattern check ✓     |
| 3    | ✅ done    | `e54962c` | `aws_iam_list_identities` async wrapper (users, roles, groups; pagination); 11 tests via moto                    |
| 4    | ✅ done    | `52f709b` | `aws_iam_simulate_principal_policy` — batches actions in chunks of 50; 8 tests via stubbed `boto3.Session`       |
| 5    | ✅ done    | `c1f2b81` | `aws_access_analyzer_findings` — paginates ListFindingsV2; 7 tests; **Q2 resolved** (reimplement, not reuse)     |
| 6    | ✅ done    | `90d176b` | `permission_path_resolver` — pure-Python flatten of simulator decisions; 22 tests; **Q3 resolved** (Phase 1 cap) |
| 7    | ✅ done    | `46a3388` | Findings normalizer — overprivilege/dormant/external/MFA-gap; 16 tests                                           |
| 8    | ⬜ pending | —         | Findings → markdown summarizer (mirror D.1 KEV-section pattern; "high-risk principals" pinned at top)            |
| 9    | ⬜ pending | —         | NLAH (README + tools.md + 2 OCSF examples + loader)                                                              |
| 10   | ⬜ pending | —         | **Use `charter.llm_adapter` directly** — first agent to consume the hoisted adapter (validates ADR-007 v1.1)     |
| 11   | ⬜ pending | —         | Agent driver — async `run()` wires charter + concurrent IAM tools + normalizer + summarizer; deterministic v0.1  |
| 12   | ⬜ pending | —         | 10 representative eval cases (overprivilege + dormant + external-access + clean account variants)                |
| 13   | ⬜ pending | —         | `IdentityEvalRunner` registered via `nexus_eval_runners` entry-point; 10/10 via `run_suite`                      |
| 14   | ⬜ pending | —         | CLI: `identity-agent eval CASES_DIR` + `identity-agent run --contract`                                           |
| 15   | ⬜ pending | —         | Package README + runbook (`runbooks/scan_aws_account.md`) + ADR-007 v1.1 conformance addendum                    |
| 16   | ⬜ pending | —         | Final verification (≥ 80% coverage; ruff/mypy clean; CLI smoke; suite-on-suite via F.2)                          |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [**ADR-007 v1.1**](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md).

---

## Key design questions (resolve in Tasks 2 + 5 + 6)

### Q1 — OCSF class

Identity findings don't slot cleanly into one OCSF v1.3 class. Three options:

- **`class_uid 3001` Authentication Activity** — overfit; this is per-event, not per-principal-state.
- **`class_uid 3005` Account Change** — closer but still per-event.
- **`class_uid 6004` Policy Result** — fits "this principal's policy evaluation" but is request-scoped.
- **Custom Nexus extension** under `category_uid 3` (Identity & Access Management) — most accurate.

Resolve in Task 2 by picking the closest existing class and adding Nexus-specific fields under `unmapped` or via an extension namespace. **Anti-pattern:** invent a brand-new class_uid; OCSF compatibility is non-negotiable per ADR-004.

### Q2 — Reuse vs reimplement IAM tools

Cloud-posture ships `aws_iam.list_users_without_mfa` and `aws_iam.list_admin_policies` already. Three options:

- **Cross-package import** — `from cloud_posture.tools.aws_iam import list_users_without_mfa`. Tightest coupling but minimal duplication.
- **Hoist into `nexus-shared`** — third-time-rule trigger; cloud-posture + identity use them, more agents probably will.
- **Reimplement in identity package** — clean separation; some duplication.

Resolve in Task 5. **Bias:** hoist into `shared.aws.iam` if the test uncovers any second copy. Mirror the ADR-007 v1.1 lesson — surface duplication early, hoist once.

### Q3 — Permission-path resolver scope

The resolver flattens `principal × policy_set → effective_grants`. Real-world AWS permission graphs are huge: 100+ principals × 10+ policies × 100+ statements with `Principal`, `Action`, `Resource`, `Condition` fields. The resolver must handle:

- Managed policies (AWS-managed + customer-managed)
- Inline policies
- Group-attached policies (transitive)
- Permission boundaries (subtractive)
- SCPs (organization-level — out of scope for v0.1)
- `Condition` fields (out of scope for v0.1; deterministic eval only)

Resolve in Task 6. **Phase 1 cap:** users + roles + groups; managed + inline; permission boundaries; no SCPs, no conditions. The output is a flat `(principal_arn, action, resource_pattern, effect)` table.

---

## File Structure

```
packages/agents/identity/
├── pyproject.toml                              # name=nexus-identity, BSL 1.1
├── README.md
├── eval/
│   └── cases/                                  # 10 representative cases (Task 12)
├── runbooks/
│   └── scan_aws_account.md                     # Task 15
├── src/identity/
│   ├── __init__.py
│   ├── py.typed
│   ├── schemas.py                              # OCSF Identity Finding (class_uid TBD)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── aws_iam.py                          # async wrappers (or import from shared)
│   │   ├── aws_access_analyzer.py
│   │   ├── permission_paths.py
│   │   └── dormant.py
│   ├── normalizer.py
│   ├── summarizer.py
│   ├── nlah_loader.py
│   ├── nlah/
│   │   ├── README.md
│   │   ├── tools.md
│   │   └── examples/
│   │       ├── 01-admin-no-mfa.md
│   │       └── 02-clean-account.md
│   ├── agent.py
│   ├── eval_runner.py
│   └── cli.py
└── tests/
    ├── test_smoke.py
    ├── test_schemas.py
    ├── test_aws_iam.py
    ├── test_aws_access_analyzer.py
    ├── test_permission_paths.py
    ├── test_dormant.py
    ├── test_normalizer.py
    ├── test_summarizer.py
    ├── test_nlah_loader.py
    ├── test_agent_unit.py
    ├── test_eval_runner.py
    ├── test_cli.py
    └── integration/
        └── test_aws_iam_localstack.py          # opt-in via NEXUS_LIVE_LOCALSTACK=1
```

**No `llm.py` in this layout** — D.2 imports `from charter.llm_adapter import ...` directly per ADR-007 v1.1.

---

## Tasks

### Task 1: Bootstrap package skeleton

Mirror [D.1 Task 1](2026-05-10-d-1-vulnerability-agent.md#task-1-bootstrap-packagesagentsvulnerability) exactly with the name swap.

- [ ] **Step 1: Write failing smoke test** — `from identity import __version__`.
- [ ] **Step 2: pyproject.toml** — name = `nexus-identity`, BSL 1.1, deps: nexus-{charter, shared, eval-framework}, boto3, pydantic, pyyaml, click, structlog. Dev extras: pytest + pytest-asyncio + moto + types-PyYAML.
- [ ] **Step 3: Implement** — `__init__.py` with `__version__`, `py.typed`, `cli.py` stub, `README.md` stub, `tests/test_smoke.py`.
- [ ] **Step 4: Update root pyproject** — add `packages/agents/identity` to `[tool.uv.workspace.members]` and `[tool.mypy.files]`.
- [ ] **Step 5: Commit** — `feat(identity): bootstrap package skeleton (D.2 task 1)`.

**Acceptance:** `uv sync --all-packages --all-extras` resolves; `uv run pytest packages/agents/identity/` collects ≥ 1 test; mypy strict clean.

---

### Task 2: OCSF Identity / Entitlement Finding schema

Resolve **Q1** (OCSF class selection). Then mirror cloud-posture's [`schemas.py`](../../../packages/agents/cloud-posture/src/cloud_posture/schemas.py) and D.1's [`schemas.py`](../../../packages/agents/vulnerability/src/vulnerability/schemas.py): Severity enum (verbatim), envelope wrapping (verbatim), FindingsReport with `count_by_severity()` + agent-specific `count_by_finding_type()` (overprivilege / dormant / external_access / mfa_gap / admin_paths / ...).

`finding_id` regex: `IDENT-<finding_type>-<principal_short_id>-<NNN>`, e.g., `IDENT-OVERPRIV-AROAUSER123ABC-001`.

- [ ] **Step 1: Write failing tests** — class_uid (chosen), severity round-trip, FindingType enum, finding_id regex, FindingsReport.count_by_finding_type.
- [ ] **Step 2: Implement** with the OCSF class chosen.
- [ ] **Step 3: Tests pass** — ≥ 12 tests.
- [ ] **Step 4: Commit** — `feat(identity): ocsf identity finding schema (D.2 task 2)`.

**ADR-007 v1.1 pattern check:** schema-as-typing-layer pattern — should generalize verbatim.

---

### Task 3: `aws_iam_list_identities` async wrapper

Per ADR-005, `boto3` calls go through `asyncio.to_thread`. Wrapper signature:

```python
async def aws_iam_list_identities(
    *,
    profile: str | None = None,
    region: str = "us-east-1",
    timeout_sec: float = 60.0,
) -> IdentityListing:
    """Returns users + roles + groups + their attached policies.

    Pagination handled internally; bounded by IAM SDK rate limits.
    """
```

`IdentityListing` is a frozen dataclass: `users`, `roles`, `groups`, `attachments` (principal → policy ARNs).

- [x] **Step 1: Write failing tests** with `moto` (`@mock_aws` in async context-manager form). Pre-seed users + roles + groups + policies.
- [x] **Step 2: Implement** — boto3 + asyncio.to*thread + paginated `list_users` / `list_roles` / `list_groups` + `list_attached*\*\_policies`.
- [x] **Step 3: Tests pass** — 11/11 (incl. 25-user pagination case).
- [x] **Step 4: Commit** — `e54962c feat(d2,f4): aws iam listing tool + auth0 management api client (D.2 + F.4 task 3)`. Bundled with F.4 Task 3.

---

### Task 4: `aws_iam_simulate_principal_policy` async wrapper

The IAM SimulatePrincipalPolicy API takes (principal, actions, resources) → permission decisions. Wrapper batches up to 50 actions per call (API limit).

- [x] **Step 1: Write failing tests** — wrapper yields one decision per (principal, action, resource) triple. Stubbed via monkey-patched `boto3.Session` because moto raises `NotImplementedError` on `simulate_principal_policy`.
- [x] **Step 2: Implement**.
- [x] **Step 3: Tests pass** — 8/8 (incl. 75-action batching split, multi-resource fan-out, error wrap).
- [x] **Step 4: Commit** — `52f709b feat(d2,f4): iam policy simulator + auth0 jwt verifier (D.2 + F.4 task 4)`. Bundled with F.4 Task 4.

---

### Task 5: `aws_access_analyzer_findings` async wrapper

Resolve **Q2** (reuse vs reimplement IAM tools).

AWS Access Analyzer surfaces external access (cross-account, public). Wrapper signature:

```python
async def aws_access_analyzer_findings(
    *,
    analyzer_arn: str,
    profile: str | None = None,
    timeout_sec: float = 60.0,
) -> list[AccessAnalyzerFinding]:
```

- [x] **Step 1: Write failing tests** — moto does not implement Access Analyzer, so we stub `boto3.Session` directly (same pattern as Task 4).
- [x] **Step 2: Implement**.
- [x] **Step 3: Tests pass** — 7/7.
- [x] **Step 4: Commit** — `c1f2b81 feat(d2,f4): access analyzer wrapper + tenant resolver (D.2 + F.4 task 5)`. Bundled with F.4 Task 5.

**Q2 resolved**: identity _reimplements_ IAM tools rather than reusing cloud-posture's, because cloud-posture's helpers are CSPM-shaped (compliance findings against CIS/PCI), identity needs richer typed dataclasses for the resolver, and cross-package import between agents violates the agent-isolation principle.

---

### Task 6: `permission_path_resolver` (custom)

Resolve **Q3** (resolver scope cap).

Pure-Python deterministic flattening: `(IdentityListing, simulator_results) → list[EffectiveGrant]`. No boto3 calls; no LLM. The resolver is the highest-leverage piece in this agent.

```python
@dataclass(frozen=True, slots=True)
class EffectiveGrant:
    principal_arn: str
    action: str
    resource_pattern: str
    effect: Literal["Allow", "Deny"]
    source_policy_arns: tuple[str, ...]   # which policies contributed
    is_admin: bool                         # `*:*` or `iam:*` etc.
```

- [x] **Step 1: Write failing tests** — covers decision-effect mapping, admin classification matrix, multi-principal grouping, source-policy attribution, and shape invariants.
- [x] **Step 2: Implement** as a pure-Python transformation over simulator output (boundary subtraction is implicit because the simulator pre-applies it).
- [x] **Step 3: Tests pass** — 22/22.
- [x] **Step 4: Commit** — `90d176b feat(d2,f4): permission-path resolver + rbac table (D.2 + F.4 task 6)`. Bundled with F.4 Task 6.

**Q3 resolved**: Phase 1 cap is users/roles/groups + managed/inline + permission boundaries. SCPs and IAM `Condition` evaluation deferred to Phase 2.

---

### Task 7: Findings normalizer

Mirror D.1's `normalizer.py` shape. Inputs: IdentityListing + EffectiveGrants + AccessAnalyzerFindings + DormantStatus. Output: `list[IdentityFinding]` (typed wrapper from Task 2).

The normalizer detects:

- **Overprivilege** — admin-equivalent grants (`*:*`, `iam:*`, etc.) on non-admin principals.
- **Dormant** — last-used timestamp older than threshold (default 90 days).
- **External access** — cross-account or public via Access Analyzer.
- **MFA gap** — admin-capable principals without MFA enforcement (re-uses cloud-posture's signal).

- [x] **Step 1: Write failing tests** — one (or more) fixture per finding type + threshold configurability + ID uniqueness + multi-finding rollup.
- [x] **Step 2: Implement** as an async-shaped pure transformation (no TaskGroup needed; all inputs pre-computed in v0.1).
- [x] **Step 3: Tests pass** — 16/16.
- [x] **Step 4: Commit** — `46a3388 feat(d2,f4): findings normalizer + scim 2.0 endpoint (D.2 + F.4 task 7)`. Bundled with F.4 Task 7.

---

### Task 8: Findings → markdown summarizer

Mirror D.1's [`summarizer.py`](../../../packages/agents/vulnerability/src/vulnerability/summarizer.py). Pin a "High-risk principals" section at the top (analogous to D.1's KEV section): principals with admin-grants OR external-access OR MFA-gap.

- [ ] **Step 1: Write failing tests** — empty + each finding type + multi-finding rollup.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass** — ≥ 8 tests.
- [ ] **Step 4: Commit** — `feat(identity): markdown summarizer with high-risk-principals section (D.2 task 8)`.

---

### Task 9: NLAH

Mirror D.1 [`nlah/`](../../../packages/agents/vulnerability/src/vulnerability/nlah/) — README + tools.md + 2 OCSF-shaped examples. Examples: (a) admin-no-MFA principal, (b) clean account.

- [ ] **Step 1: Write the four files**.
- [ ] **Step 2: Loader test** — copy-with-rename of D.1's nlah_loader test (8 tests).
- [ ] **Step 3: Tests pass**.
- [ ] **Step 4: Commit** — `feat(identity): nlah (D.2 task 9)`.

**Pattern check:** the loader is also identical to cloud-posture's. **Candidate for hoisting into `charter.nlah_loader`** — log this and surface in Task 16's conformance review.

---

### Task 10: LLM adapter — `from charter.llm_adapter import ...`

The whole point of ADR-007 v1.1. **Do not create a per-agent `llm.py`.** The agent driver (Task 11) imports directly:

```python
from charter.llm_adapter import LLMConfig, make_provider, config_from_env
```

This task validates the hoist: if the import works without modification across agent boundaries, ADR-007 v1.1 is twice-confirmed.

- [ ] **Step 1: Confirm import works** — `python -c "from charter.llm_adapter import LLMConfig, make_provider, config_from_env"` succeeds.
- [ ] **Step 2: No new tests** — the canonical 19 tests at `packages/charter/tests/test_llm_adapter.py` already cover the surface.
- [ ] **Step 3: Commit** — `chore(identity): consume charter.llm_adapter (D.2 task 10; adr-007 v1.1)`.

**Note:** Task 11's agent.run signature accepts `llm_provider: LLMProvider | None = None` per the canon; the adapter is wired through but not called in v0.1 deterministic flow.

---

### Task 11: Agent driver

Mirror D.1's [`agent.py`](../../../packages/agents/vulnerability/src/vulnerability/agent.py). The flow:

1. Charter context manager.
2. Concurrent IAM-listing + Access-Analyzer fetch (`asyncio.TaskGroup`).
3. Permission-path resolution (deterministic).
4. Dormant-identity detection (last-used timestamps from IAM).
5. Normalizer → OCSF findings.
6. `findings.json` + `summary.md` written via `ctx.write_output`.
7. Charter exits → `assert_complete`.

Signature:

```python
async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider | None = None,
    aws_account_id: str = DEFAULT_AWS_ACCOUNT_ID,
    aws_region: str = DEFAULT_AWS_REGION,
    profile: str | None = None,
    enrich: bool = True,
) -> FindingsReport:
```

- [ ] **Step 1: Write failing tests** — clean account → 0 findings; admin-no-MFA fixture → 1 finding; multi-finding fixture → correct rollup.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass** — ≥ 10 tests.
- [ ] **Step 4: Commit** — `feat(identity): agent driver wiring charter + iam tools (D.2 task 11)`.

---

### Task 12: 10 representative eval cases

Per D.1 Task 12 shape. Cases:

| #   | Title                        | Fixture                                                                      | Expected                                       |
| --- | ---------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------- |
| 001 | clean_account                | empty IAM listing                                                            | finding_count=0                                |
| 002 | admin_no_mfa                 | one user with `AdministratorAccess` and no MFA                               | 1 high finding (overpriv + mfa_gap merge)      |
| 003 | dormant_admin                | admin role last used 200 days ago                                            | 1 high finding (dormant)                       |
| 004 | external_access_role         | role with cross-account trust policy                                         | 1 high finding (external_access)               |
| 005 | inline_overpriv              | user with inline `*:*` policy                                                | 1 critical finding (overpriv)                  |
| 006 | group_transitive             | user gets admin via group membership                                         | 1 high finding (overpriv attributed correctly) |
| 007 | permission_boundary_subtract | admin-attached policy + boundary that strips `iam:*` → effective non-admin   | 0 findings (boundary correctly subtracts)      |
| 008 | dormant_human_user           | last-used > 90 days for a human user                                         | 1 medium finding (dormant)                     |
| 009 | service_role_dormant         | service role flagged with `service: true` annotation, last used 200 days ago | 0 findings (service roles exempt from dormant) |
| 010 | mixed_findings               | combination of overpriv + external + dormant                                 | 3 findings, correct severity rollup            |

- [ ] **Step 1: Write the 10 YAML files.**
- [ ] **Step 2: Iterate fixtures** until 10/10 pass via Task 13's runner.
- [ ] **Step 3: Commit** — `feat(identity): 10 representative eval cases (D.2 task 12)`.

---

### Task 13: `IdentityEvalRunner` + entry-point registration

Mirror D.1 [`eval_runner.py`](../../../packages/agents/vulnerability/src/vulnerability/eval_runner.py) shape. Patches the IAM tool wrappers + Access Analyzer wrapper per `case.fixture`. Patches the **normalizer's local bindings** of any HTTP / network calls (mirror D.1's lesson on patching at the right scope).

`pyproject.toml`:

```toml
[project.entry-points."nexus_eval_runners"]
identity = "identity.eval_runner:IdentityEvalRunner"
```

- [ ] **Step 1: Write failing tests** — Protocol satisfaction + happy + mismatch + 10/10 acceptance gate.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Verify entry-point** — `uv run eval-framework run --runner identity --cases ... --output ...` prints `10/10 passed`.
- [ ] **Step 4: Commit** — `feat(identity): identityevalrunner against the eval-framework (D.2 task 13)`.

---

### Task 14: CLI

Mirror D.1's [`cli.py`](../../../packages/agents/vulnerability/src/vulnerability/cli.py): `identity-agent eval CASES_DIR` + `identity-agent run --contract path.yaml [--profile aws-profile]`.

- [ ] **Step 1: Write failing tests** via Click's CliRunner.
- [ ] **Step 2: Implement**.
- [ ] **Step 3: Tests pass** — ≥ 5 tests.
- [ ] **Step 4: Commit** — `feat(identity): cli with eval + run subcommands (D.2 task 14)`.

---

### Task 15: README + runbook + ADR-007 v1.1 conformance

README pattern from D.1. Runbook is `runbooks/scan_aws_account.md` — mirrors cloud-posture's AWS dev-account runbook with identity-specific signals (admin-no-MFA, dormant, external-access).

ADR-007 v1.1 conformance addendum:

| Pattern (10 in canon)                 | D.2 verdict (filled out as tasks land)   |
| ------------------------------------- | ---------------------------------------- |
| Schema-as-typing-layer                | Task 2 verdict                           |
| Async-by-default tool wrappers        | Tasks 3 + 4 + 5                          |
| HTTP-wrapper convention               | n/a (boto3 only)                         |
| Concurrent TaskGroup enrichment       | Task 7 / 11                              |
| Markdown summarizer                   | Task 8                                   |
| NLAH layout                           | Task 9 — **candidate for charter hoist** |
| LLM adapter via `charter.llm_adapter` | Task 10 — **post-amendment validation**  |
| Charter context + agent.run shape     | Task 11                                  |
| Eval-runner via entry-point group     | Task 13                                  |
| CLI subcommand pattern                | Task 14                                  |

- [ ] **Step 1: Write README** + runbook + addendum.
- [ ] **Step 2: Update version-history**.
- [ ] **Step 3: Commit** — `docs(identity): readme + runbook + adr-007 v1.1 conformance (D.2 task 15)`.

---

### Task 16: Final verification

Mirror D.1's gate set:

1. `uv run pytest packages/agents/identity/ --cov=identity --cov-fail-under=80` — ≥ 80%.
2. `uv run ruff check packages/agents/identity/` + `uv run ruff format --check ...` + `uv run mypy ...` — all clean.
3. `uv run identity-agent eval packages/agents/identity/eval/cases` — `10/10 passed`.
4. `uv run eval-framework run --runner identity --cases ... --output suite.json` — same.
5. `uv run eval-framework gate suite.json --config <(echo 'min_pass_rate: 1.0')` — exit 0.
6. **ADR-007 v1.1 conformance review** — confirm the LLM-adapter hoist worked end-to-end (no `identity/llm.py` was created); flag any new amendments (e.g., `nlah_loader.py` hoist).

Capture `docs/_meta/d2-verification-<date>.md` mirroring D.1's record.

- [ ] **Step 1: Run all six gates.**
- [ ] **Step 2: Write verification record.**
- [ ] **Step 3: Re-issue system-readiness with timestamp** — D.2 done; weighted Wiz coverage ~14–16% (CIEM 0.10 × ~30% template parity = +3pp).
- [ ] **Step 4: Commit** — `docs(d2): final verification + readiness re-issue`.

**Acceptance:** Identity Agent runs end-to-end against the eval framework. ADR-007 v1.1 confirmed. Any new amendment recommendations queued for ADR-007 v1.2 before D.3.

---

## Self-Review

**Spec coverage** (build-roadmap entry "Cartography, AWS IAM Access Analyzer, custom permission simulator"):

- ✓ AWS IAM Access Analyzer — Task 5.
- ✓ Custom permission simulator — Task 6 (the resolver) + Task 4 (SimulatePrincipalPolicy).
- ✗ Cartography — **deferred** to D.7 Investigation Agent. Cartography is a graph database (Neo4j-backed); Identity v0.1 uses direct boto3 calls. Cartography integration belongs with cross-agent enrichment.

**ADR-007 v1.1 conformance points the plan tests:**

- ✓ Schema-as-typing-layer (Task 2).
- ✓ Async-by-default tool wrappers (Tasks 3–5).
- ✓ Concurrent TaskGroup enrichment (Task 7 / 11).
- ✓ NLAH layout (Task 9; flag for hoist if test confirms duplication).
- ✓ **LLM adapter via `charter.llm_adapter`** — Task 10 is the explicit ADR-007 v1.1 validation.
- ✓ Charter context + agent.run shape (Task 11).
- ✓ Eval-runner via entry-point group (Task 13).
- ✓ CLI subcommand pattern (Task 14).
- n/a HTTP-wrapper convention — Identity is boto3-only.

**Defers:**

- Azure / GCP IAM (Phase 2 multi-cloud).
- Cartography (D.7 Investigation Agent).
- JIT access (Phase 1c after Tier-2 remediation).
- SaaS identity (D.10 SSPM).
- IAM `Condition` field evaluation in the resolver.

**Type / name consistency:**

- Package import name: `identity`.
- Agent name: `identity`.
- Eval runner registration name: `identity` (so `eval-framework run --runner identity` works).
- CLI binary: `identity-agent`.

**Acceptance for D.2 as a whole:** Identity Agent ships end-to-end. ADR-007 v1.1 is confirmed by the second consumer. Any new amendments queued before D.3 starts. Weighted Wiz coverage moves from ~11.8% → ~14–16%.

---

## References

- [D.1 plan](2026-05-10-d-1-vulnerability-agent.md) — first reference template; ADR-007 v1.1 amendment trigger.
- [D.1 verification record](../../_meta/d1-verification-2026-05-11.md) — gate-by-gate proof.
- [F.3 plan](2026-05-08-f-3-cloud-posture-reference-nlah.md) — original reference template.
- [F.2 plan](2026-05-10-f-2-eval-framework-v0.1.md) — eval framework D.2 registers into.
- [Build roadmap](2026-05-08-build-roadmap.md) — D.2 entry.
- ADRs: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-002](../../_meta/decisions/ADR-002-charter-as-context-manager.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [**ADR-007 v1.1**](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md).
