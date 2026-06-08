# F.3 Cloud Posture v0.2 — hoist-candidate documentation (Q7) (2026-06-08)

> **F.3 v0.2 Milestone 4, Task 12.** A **forward-looking inventory** of the in-package patterns F.3 v0.2 established, so the next agent that needs them can lift them to `charter` deliberately. **This is documentation, not a hoist** — no `packages/charter/**` is touched; the substrate seal stays empty. API shapes below are verified against current `main`.

---

## §1. Context

- **Q7 (F.3 v0.2 brainstorm §7):** establish these patterns **in-package** (`packages/agents/cloud-posture/`), document them as hoist candidates, and **do not hoist to `charter` this cycle**.
- **[ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md) third-consumer rule:** a pattern hoists to `charter` when a **third** agent needs it — premature hoisting on a sample size of one bakes AWS assumptions into a cloud-agnostic substrate.
- **Consumer count today:** F.3 is the **1st** consumer (now). **D.5 Multi-Cloud Posture v0.2** is the likely **2nd**; **D.2 Identity v0.2** the likely **3rd** → the **3rd** adoption is the hoist trigger.
- This document makes the candidates **findable** so the D.5 v0.2 brainstorm (next on the strict-serial track) can act on them without spelunking F.3 source. **No hoist is executed here.**

## §2. Hoist-candidate patterns (5, from F.3 v0.2)

### Pattern A — Credential-resolution seam

- **Current location:** [`src/cloud_posture/credentials.py`](../../packages/agents/cloud-posture/src/cloud_posture/credentials.py)
- **Established in:** Task 2 (#254)
- **Proposed charter location:** `packages/charter/src/charter/cloud/credentials.py`
- **API shape (verified):** `CredentialResolver(*, profile: str | None = None)`; `.profile -> str | None`; `.resolve_session() -> boto3.Session`; `.client(service: str, *, region: str | None = None) -> client`. Only state is the profile **name** — no secret material is stored or logged.
- **What stays in-agent:** the `boto3.Session` construction and AWS client wiring.
- **What hoists:** the abstract _"resolve a per-run cloud session from a profile name / default chain"_ contract — the seam shape and the no-secrets invariant are cloud-agnostic.
- **Third-consumer trigger:** D.2 Identity v0.2 (CIEM needs a credential seam across clouds).
- **Hoist effort:** **medium** — the seam generalizes cleanly, but per-cloud session equivalents (Azure/GCP) need their own design behind the same contract.

### Pattern B — Account + region autodiscovery

- **Current location:** [`src/cloud_posture/tools/aws_account_discovery.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_account_discovery.py)
- **Established in:** Task 3 (#255)
- **Proposed charter location:** `packages/charter/src/charter/cloud/account_discovery.py`
- **API shape (verified):** `async discover_account_id(resolver: CredentialResolver) -> str` (STS `get_caller_identity`); `async discover_regions(resolver: CredentialResolver) -> list[str]` (EC2 region enumeration).
- **What stays in-agent:** the AWS STS call + EC2 region enumeration.
- **What hoists:** the abstract _"discover the account scope + the regions to scan, given a resolver"_ contract per cloud.
- **Third-consumer trigger:** D.5 v0.2 (subscription discovery / project discovery have the same _shape_, different _scope model_).
- **Hoist effort:** **large** — each cloud's account/scope model diverges most here (account vs subscription vs project); the contract hoists, the per-cloud discovery does not.

### Pattern C — Region scoping (precedence + signature)

- **Current location:** [`src/cloud_posture/agent.py`](../../packages/agents/cloud-posture/src/cloud_posture/agent.py) (`run(...)` region threading)
- **Established in:** Task 4 (#256)
- **Proposed charter location:** a base-agent contract — `BaseAgent.run(..., regions: list[str] | None, discover_all_regions: bool)`.
- **API shape (verified):** precedence in `run()` — explicit `regions` **→** `discover_all_regions` (enumerate all) **→** `[aws_region]` single-region fallback.
- **What stays in-agent:** per-cloud region enumeration (AWS `ec2` regions ≠ Azure locations ≠ GCP regions).
- **What hoists:** the **precedence logic** + the `run()` signature shape.
- **Third-consumer trigger:** D.5 v0.2 (same precedence over its own region/scope list).
- **Hoist effort:** **small** — the precedence logic is cloud-agnostic.

### Pattern D — Live-eval lane gating

- **Current location:** [`src/cloud_posture/live_lane.py`](../../packages/agents/cloud-posture/src/cloud_posture/live_lane.py) + the `aws_live_account` fixture in [`tests/integration/conftest.py`](../../packages/agents/cloud-posture/tests/integration/conftest.py)
- **Established in:** Task 6 (#259)
- **Proposed charter location:** `packages/charter/src/charter/testing/live_lanes.py`
- **API shape (verified):** `nexus_live_aws_enabled() -> bool`; `aws_reachable() -> tuple[bool, str]`; `aws_skip_reason() -> str | None`. Generalized: `nexus_live_<cloud>_enabled()` / `<cloud>_reachable()` / `<cloud>_skip_reason()`.
- **What stays in-agent:** the per-cloud reachability **probe** (AWS STS `get_caller_identity`; other clouds use their own).
- **What hoists:** the env-gating + skip-message + reachability-check **shape**, plus the lane-independence contract ([`test_lane_coexistence.py`](../../packages/agents/cloud-posture/tests/integration/test_lane_coexistence.py), Task 8).
- **Third-consumer trigger:** D.5 v0.2 (new env-gated lanes need exactly this shape — see §3).
- **Hoist effort:** **small** — gating is generic; only the probe stays per-cloud.

### Pattern E — Partial-scan degradation

- **Current location:** [`src/cloud_posture/agent.py`](../../packages/agents/cloud-posture/src/cloud_posture/agent.py) (per-region `try/except` → `degraded_regions`) + `_sanitize_scan_error` + [`summarizer.py`](../../packages/agents/cloud-posture/src/cloud_posture/summarizer.py) `_append_degraded`
- **Established in:** Task 5 (#257)
- **Proposed charter location:** a base-agent contract — the degraded-unit emission pattern.
- **API shape (verified):** a per-unit failure is recorded as a structured degraded marker (`{"region": …, "error": <sanitized>}`) surfaced in `summary.md`; the scan **continues** — it is **not** a whole-run failure. `BudgetExhausted` is the one hard-stop. Error strings are secret-free + traceback-free.
- **What stays in-agent:** the per-cloud error taxonomy (boto3 `ClientError` ≠ Azure SDK errors ≠ GCP gax errors).
- **What hoists:** the **degradation contract** + the degraded-marker shape.
- **Third-consumer trigger:** D.5 v0.2 (per-subscription / per-project partial scans need the same behavior).
- **Hoist effort:** **small** — the contract is cloud-agnostic; only the error-mapping is per-cloud.

## §3. Naming-convention proposals (future per-cloud lanes)

For the live-eval lanes future agents will add (named here only as forward triggers, not as F.3 capabilities):

| Env gate             | Owner     | Status              |
| -------------------- | --------- | ------------------- |
| `NEXUS_LIVE_AWS=1`   | F.3       | **exists** (Task 6) |
| `NEXUS_LIVE_AZURE=1` | D.5 v0.2  | proposed            |
| `NEXUS_LIVE_GCP=1`   | D.5 v0.2  | proposed            |
| `NEXUS_LIVE_OCI=1`   | D.5 v0.3+ | future              |

Proposed charter dispatcher when Pattern D hoists: `nexus_live_cloud_enabled(cloud: str) -> bool`.

## §4. Explicit non-hoist items (stay in F.3 forever)

**Principle: patterns hoist; cloud-specific implementations do not.** These are AWS-specific by design and must **never** move to `charter`:

- [`tools/prowler.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py) — AWS-specific Prowler binary invocation.
- [`tools/aws_iam.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py) — AWS IAM API calls.
- [`tools/aws_s3.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py) — AWS S3 API calls.
- AWS-specific OCSF 2003 field mapping (`account_uid`, AWS region naming, ARN shapes).
- AWS Cloud Custodian integration (v0.3, also AWS-specific).

## §5. Hoist sequencing recommendation (for the D.5 v0.2 brainstorm)

Order by ascending effort / divergence, so the cheap wins land first:

1. **Pattern D — live-lane gating** (small) — easiest hoist; the D.5 lanes need it immediately.
2. **Pattern E — partial-scan degradation** (small) — pairs with D.
3. **Pattern C — region scoping** (small) — pairs with the above.
4. **Pattern A — CredentialResolver** (medium) — after D.5's per-cloud credential needs are explicit.
5. **Pattern B — account autodiscovery** (large) — last; most cloud divergence.

**Cadence ([ADR-011](decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)):** each hoist is its **own SAFETY-CRITICAL PR** (it touches `charter`, so the WI-1 substrate seal will red `python-tests` — by design). A short hoist plan-doc → per-pattern PRs, not a batch.

## §6. Cross-references

- [ADR-007 — Cloud Posture as the reference agent](decisions/ADR-007-cloud-posture-as-reference-agent.md) (third-consumer rule)
- [ADR-010 — version-extension template](decisions/ADR-010-version-extension-template.md)
- [ADR-011 — PR-flow + branch-protection discipline](decisions/ADR-011-pr-flow-and-branch-protection-discipline.md)
- Task PRs establishing the patterns: **#254** (A) · **#255** (B) · **#256** (C) · **#259** (D) · **#257** (E)
- [F.3 v0.2 plan](../superpowers/plans/2026-06-07-f-3-cloud-posture-v0-2.md)
- F.3 v0.2 verification record — cycle-closure artifact (Task 13, opens after this PR merges): `docs/_meta/f-3-cloud-posture-v0-2-verification-*.md`
- D.5 Multi-Cloud Posture v0.2 brainstorm — forthcoming (next cycle); first consumer of these candidates.

---

— recorded 2026-06-08 (F.3 v0.2 Task 12; Q7 hoist-candidate inventory; documentation only, charter untouched).
