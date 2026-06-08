# F.3 Cloud Posture v0.2 — AWS CSPM coverage `[estimate]` note (2026-06-08)

> **F.3 v0.2 Milestone 4, Task 11.** Measures F.3 v0.2's **AWS CSPM coverage** against the macro-plan target (84% → ~90%) and reports it honestly. **Scope: AWS CSPM only** — F.3 is architecturally AWS-only ([ADR-007](decisions/ADR-007-cloud-posture-as-reference-agent.md)); every figure below is **AWS CSPM coverage**, never an unqualified "CSPM" number. Other clouds are out of scope for this agent (separate agents/cycles).
>
> **Every percentage here is an `[estimate]`, not an instrumented ratio** — see §3.

---

## §1. Headline

**F.3 v0.2 AWS CSPM coverage: ~84% → ~84% `[estimate]` — no movement.**

v0.2 was a **Level-2 operational-maturity** cycle (offline → live AWS), **not** a rule-breadth cycle. It added live boto3, credential resolution, current-account autodiscovery, region scoping, live-AWS error handling / partial-scan degradation, and gated eval/integration lanes — **none of which add AWS detection rules.** The macro plan's hoped **84% → ~90%** for this step ([roadmap §3](../strategy/nexus-agent-maturity-roadmap-2026-06-07.md)) is **not reached by v0.2**, and that is the honest result: live mode alone does not expand AWS CSPM **rule** coverage. The ~90% lift is a **v0.3** rule-library task (see §5).

What v0.2 _did_ change — and what the flat percentage understates — is that the ~84% AWS CSPM rule coverage moved from **offline-fixture-only** to **live, real-account, all-region** (operationally usable). That is a real maturity gain on the _liveness_ axis, not on the _rule-breadth_ axis the percentage tracks.

## §2. Methodology

**Baseline — "100% Wiz AWS CSPM."** Taken as Wiz's continuous, agentless AWS CSPM: its full AWS misconfiguration rule set + config-graph context. There is **no public, enumerable denominator** for it, so the baseline is the qualitative "complete AWS CSPM" target the macro plan already pegged F.3 against.

**F.3's current AWS rule inventory (v0.2 = v0.1, unchanged):**

- **Prowler 5.x AWS ruleset** (external binary; the breadth engine) — hundreds of AWS checks; the roadmap pegs current pattern breadth at ~700 ([roadmap §3](../strategy/nexus-agent-maturity-roadmap-2026-06-07.md)).
- **3 native boto3 detectors** ([`tools/aws_iam.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py), [`tools/aws_s3.py`](../../packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py)): users-without-MFA, customer-managed `*:*` admin policy, S3 enrichment.
- **Rule-id map** ([`agent.py`](../../packages/agents/cloud-posture/src/cloud_posture/agent.py) `_PROWLER_RULE_MAP`): 6 mapped Prowler CheckIDs (`iam_user_no_mfa`, `s3_bucket_public_access`, `s3_bucket_no_encryption`, `kms_key_no_rotation`, `rds_unencrypted`, `open_security_group`) + a stable synthetic `CSPM-AWS-PROWLER-NNN` fallback for any unmapped Prowler check.

**v0.2 capabilities added (all operational, none rule-breadth):** live boto3 (Tasks 2–3) · `--aws-profile` credential resolution (Task 2) · current-account autodiscovery (Task 3) · `--regions` scoping (Task 4) · live-AWS error handling + partial-scan degradation (Task 5) · `NEXUS_LIVE_AWS=1` lane + live integration tests + LocalStack coexistence (Tasks 6–8).

**The math.** AWS CSPM rule coverage is a function of the **rule inventory** vs the (qualitative) Wiz AWS CSPM target. The rule inventory above is **byte-for-byte the v0.1 inventory** — no `_PROWLER_RULE_MAP` entries added, no native detectors added, no Prowler version bump (the v0.2 task commits touch only credentials/discovery/region/error/lane/docs surfaces). With the numerator (rules) unchanged and the denominator (Wiz AWS CSPM) unchanged, the estimate **stays at ~84%**.

**Why `[estimate]`, not instrumented.** (1) Wiz's AWS CSPM scope is not published as a countable denominator. (2) Prowler's AWS ruleset is an external binary, not pinned/counted in-repo, so there is no in-repo rule count to ratio against. (3) The ~84% is a prior **judgement** carried forward — the macro plan pegs F.3's AWS CSPM at 84% ([roadmap §3](../strategy/nexus-agent-maturity-roadmap-2026-06-07.md), F.3 row). This note **re-confirms** that judgement is unchanged by v0.2 — it does not instrument a new ratio.

## §3. Result (verbatim)

| Axis                                                                      |            v0.1 |                               v0.2 | Delta                       |
| ------------------------------------------------------------------------- | --------------: | ---------------------------------: | --------------------------- |
| **AWS CSPM rule coverage** `[estimate]`                                   |            ~84% |                           **~84%** | **0 (no movement)**         |
| AWS rule inventory (Prowler ruleset + native detectors + mapped rule-ids) |       unchanged |                      **unchanged** | 0 rules added               |
| Operational mode (liveness axis, not a coverage %)                        | offline fixture | **live, real-account, all-region** | matured (not a rule-% gain) |

**No movement off ~84%.** Reported as measured — **not** rounded up to the macro-plan target. The macro plan's 84% → ~90% for the live step is a **hope, not a measured outcome**; v0.2 does not reach it because live mode alone does not expand AWS CSPM rule coverage.

## §4. What would move the AWS CSPM coverage number

Rule-library growth — **not** more liveness. That is a **v0.3** task and is already on F.3's deferred list: see the **"Deferred to v0.3"** line in [`packages/agents/cloud-posture/README.md`](../../packages/agents/cloud-posture/README.md) (rule expansion ~700 → 1,200+, plus the cross-account / Organizations / Control Tower items). Not duplicated here.

## §5. Verdict

**F.3 v0.2 AWS CSPM coverage holds at ~84% `[estimate]` — honest no-movement.** v0.2 is an operational-maturity ship (offline → live AWS), which makes the existing ~84% AWS CSPM rule coverage real and usable against live accounts, but does not expand the AWS rule inventory. The 84% → ~90% lift is the v0.3 AWS rule-library expansion. No number was inflated to match the macro-plan target.

---

— recorded 2026-06-08 (F.3 v0.2 Task 11; AWS CSPM coverage `[estimate]`, honest no-movement; docs-only, no code touched).
