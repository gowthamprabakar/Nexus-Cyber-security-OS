# D.5 Multi-Cloud Posture v0.2 — GCP CSPM coverage `[estimate]` note (2026-06-09)

> **D.5 v0.2 Milestone 6, Task 18 (GCP half).** Measures **GCP CSPM coverage only** — a **separate** measurement from the [Azure note](d-5-multi-cloud-posture-v0-2-azure-coverage-2026-06-09.md) per **WI-D1** (no aggregate "multi-cloud CSPM" number; no averaging; no comparison to F.3's AWS CSPM). Every figure is an `[estimate]`, not an instrumented ratio.

## §1. Headline

**GCP native CSPM coverage: ~5 native rules → ~15 native rules `[estimate]` — native detection expanded ~3×.**

GCP already had **~5 native IAM-binding rules** ([`tools/gcp_iam.py`](../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/tools/gcp_iam.py), tagged `GCP_IAM`). v0.2 adds **10 new non-IAM CIS-GCP rules** ([`rules_gcp/cis_rules.py`](../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/rules_gcp/cis_rules.py), tagged `GCP_NATIVE`) → **~15 native GCP detections total**.

## §2. Methodology

- **Baseline ("100% GCP CSPM"):** the full **CIS Google Cloud Platform Foundation Benchmark** (~100+ recommendations) + a continuous config view. No public enumerable denominator → qualitative target.
- **D.5 GCP rule inventory at v0.2:** **~15 native rules** = ~5 existing IAM-binding rules (`GCP_IAM`) + **10 new CIS-GCP rules** (`GCP_NATIVE`) across 6 resource types (storage public + uniform-access; Cloud SQL public-IP + no-SSL; GCE external-IP + default-SA-editor; firewall SSH/RDP from 0.0.0.0/0; KMS rotation; BigQuery public) — all `Source: Nexus-native`. The **SCC passthrough** remains as a complementary, **provenance-tagged third-party** source (Q7).
- **Why `[estimate]`:** the CIS-GCP denominator is not a countable in-repo value; the native rule count (~15) is exact, the _percentage_ is a judgement.

## §3. Result (verbatim, honest)

| Axis                                  |              v0.1 |                                 v0.2 | Delta             |
| ------------------------------------- | ----------------: | -----------------------------------: | ----------------- |
| **Native GCP rules**                  | **~5** (IAM only) |           **~15** (IAM + 10 CIS-GCP) | **+10 (~3×)**     |
| Native GCP CSPM coverage `[estimate]` | low single digits | **~10–12%** of the CIS-GCP benchmark | modest, real      |
| SCC passthrough                       |           present |      present (now provenance-tagged) | unchanged breadth |

**No inflation (WI-D3).** ~15 rules is a **starting subset** of the CIS-GCP benchmark, so native coverage is **low double digits at most** — reported as such, not rounded up. v0.2 broadened GCP detection beyond IAM (into storage / SQL / GCE / firewall / KMS / BigQuery); the full CIS-GCP library is **v0.3** (Q4); removal of the SCC passthrough is **v0.3** (WI-D7).

## §4. Verdict

**GCP native CSPM at v0.2: ~15 native rules (~3× the v0.1 IAM-only set) — native coverage is a modest `[estimate]` (~10–12% of CIS-GCP), reported honestly.** Breadth is v0.3 rule-library work.

---

— recorded 2026-06-09 (D.5 v0.2 Task 18, GCP half; per-cloud `[estimate]`, honest; docs-only).
