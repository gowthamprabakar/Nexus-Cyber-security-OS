# compliance v0.2 — CIS-AWS Coverage (WI-C1)

**Date:** 2026-06-11 · Measured **per-framework**, no aggregate (WI-C1).

## Covered at v0.2

- CIS AWS Foundations Benchmark v3.0 library: **43 controls**, **14 wired** to source rules.
- Wiring is **honest** (operator-confirmed 2026-06-11): a control wires ONLY to a rule a
  sibling agent actually emits. F.3 cloud-posture emits **7 stable** CIS-mappable AWS rule
  ids (IAM-001/002, S3-001/002, KMS-001, RDS-001, EC2-001) + a hash-bucketed Prowler
  passthrough; data-security adds a few S3 rules. test_cis_aws_wiring.py guards against drift.

## NOT covered (Phase D / v0.3)

- The ~29 controls (CloudTrail, Config, GuardDuty, VPC flow logs, password policy, MFA on
  root, …) with **no matching emitter rule** — broader coverage tracks F.3/DSPM expanding
  their stable rule catalogs, NOT compliance fabricating mappings.

## Honest estimate

**~30% `[estimate]`** control coverage (14/43), capped by F.3's 7-rule AWS surface — the
directive's "wire all 44" premise was corrected against ground-truth. Estimate, not a
measured benchmark.
