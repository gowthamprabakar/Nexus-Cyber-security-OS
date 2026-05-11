# Tools reference

Every tool below is async (per [ADR-005](../../../../../docs/_meta/decisions/ADR-005-async-tool-wrapper-convention.md)). Permissions and budget impact go through the runtime charter.

## `aws_iam_list_identities`

Enumerate all IAM principals in an AWS account.

**Signature:** `await aws_iam_list_identities(*, profile=None, region="us-east-1", timeout_sec=60.0)`

**Output:** `IdentityListing(users, roles, groups)` — each principal carries `attached_policy_arns`, `inline_policy_names`, plus per-type fields: `group_memberships` (users), `assume_role_policy_document` (roles), `member_user_names` (groups).

**Side effects:** boto3 calls — `list_users` / `list_roles` / `list_groups` and their attached/inline policy paginators, wrapped in `asyncio.to_thread`.

## `aws_iam_simulate_principal_policy`

Run IAM SimulatePrincipalPolicy against a principal across a (possibly large) action set.

**Signature:** `await aws_iam_simulate_principal_policy(*, principal_arn, actions, resources=("*",), profile=None, region="us-east-1", timeout_sec=60.0)`

**Output:** `tuple[SimulationDecision, ...]` — one decision per `(action, resource)` pair. `decision` is the raw IAM string (`allowed` / `explicitDeny` / `implicitDeny`).

**Notes:** Batches actions in chunks of 50 (the IAM API hard limit). Permission boundaries are pre-applied by the simulator.

## `aws_access_analyzer_findings`

Paginate AWS Access Analyzer findings (cross-account + public resource access).

**Signature:** `await aws_access_analyzer_findings(*, analyzer_arn, profile=None, region="us-east-1", statuses=("ACTIVE",), timeout_sec=60.0)`

**Output:** `tuple[AccessAnalyzerFinding, ...]` with `external_principals`, `actions`, `is_public`, `status`, `finding_type`.

**Notes:** Paginated via `nextToken`. moto does not implement Access Analyzer, so eval fixtures use canned responses.

## `permission_paths.resolve_effective_grants`

Pure-Python deterministic flattening from `(IdentityListing, SimulationDecision[]) → tuple[EffectiveGrant, ...]`.

**Signature:** `resolve_effective_grants(listing, simulator_results) -> tuple[EffectiveGrant, ...]`

**Output:** `EffectiveGrant(principal_arn, action, resource_pattern, effect, source_policy_arns, is_admin)`. `effect` is `"Allow"` or `"Deny"`; `implicitDeny` is dropped.

**Notes:** No boto3 calls; no LLM. The normalizer (Task 7) consumes this output.

## `normalizer.normalize_to_findings`

Turn the inventory + grants + Access-Analyzer findings + MFA signal into OCSF Identity Findings.

**Signature:** `await normalize_to_findings(listing, grants, access_analyzer_findings, *, envelope, detected_at=None, dormant_threshold_days=90, users_with_mfa=frozenset())`

**Output:** `list[IdentityFinding]`. Order is: overprivilege, dormant, external-access, mfa-gap.

**Notes:** Async-shaped for symmetry with D.1; body is sync in v0.1. `users_with_mfa` is the MFA signal supplied by the caller (typically cloud-posture's helpers).
