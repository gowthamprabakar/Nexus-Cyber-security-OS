# D.5 Multi-Cloud Posture v0.2 — Azure CSPM coverage `[estimate]` note (2026-06-09)

> **D.5 v0.2 Milestone 6, Task 18 (Azure half).** Measures **Azure CSPM coverage only** — a **separate** measurement from the [GCP note](d-5-multi-cloud-posture-v0-2-gcp-coverage-2026-06-09.md) per **WI-D1** (no aggregate "multi-cloud CSPM" number; no averaging; no comparison to F.3's AWS CSPM). Every figure is an `[estimate]`, not an instrumented ratio.

## §1. Headline

**Azure native CSPM coverage: 0 native rules → 8 native CIS-Azure rules `[estimate]` — the zero-native-rule gap is CLOSED.**

The honest story is **not a percentage** — it is the **milestone**: before v0.2, the Azure side was a **pure Microsoft Defender passthrough with zero Nexus-native rules** (Nexus re-formatted a competitor's findings). v0.2 ships **8 native CIS-Azure rules** ([`rules_azure/cis_rules.py`](../../packages/agents/multi-cloud-posture/src/multi_cloud_posture/rules_azure/cis_rules.py)) — **Nexus now detects Azure misconfigurations itself**.

## §2. Methodology

- **Baseline ("100% Azure CSPM"):** the full **CIS Microsoft Azure Foundations Benchmark** (~100+ recommendations) + a continuous config view. No public enumerable denominator → the baseline is the qualitative "complete Azure CSPM" target.
- **D.5 Azure rule inventory at v0.2:** **8 native CIS-Azure rules** across 5 resource types (storage public-access + secure-transfer; key-vault soft-delete + purge-protection; NSG SSH/RDP-from-any; SQL public; App Service HTTPS-only) — emitting `Source: Nexus-native`. The **Microsoft Defender passthrough** remains as a complementary, **provenance-tagged third-party** source (Q7).
- **Why `[estimate]`:** the CIS-Azure denominator is not a countable in-repo value; the native rule count (8) is exact, the _percentage_ is a judgement.

## §3. Result (verbatim, honest)

| Axis                                    |    v0.1 |                                 v0.2 | Delta               |
| --------------------------------------- | ------: | -----------------------------------: | ------------------- |
| **Native CIS-Azure rules**              |   **0** |                                **8** | **+8 (gap closed)** |
| Native Azure CSPM coverage `[estimate]` |     ~0% | **~5–8%** of the CIS-Azure benchmark | small but real      |
| Defender passthrough                    | present |      present (now provenance-tagged) | unchanged breadth   |

**No inflation (WI-D3).** ~8 rules is a **starting subset** of the CIS-Azure benchmark, so the native percentage is **low single digits** — reported as such, not rounded up. The value of v0.2 is **establishing native Azure detection from zero**, not breadth. The full CIS-Azure library is **v0.3** (Q4); removal of the Defender passthrough is **v0.3** (WI-D7).

## §4. Verdict

**Azure native CSPM at v0.2: 8 native rules, the zero-native-rule gap closed — native coverage is a small `[estimate]` (~5–8% of CIS-Azure), reported honestly.** Breadth is v0.3 rule-library work.

---

— recorded 2026-06-09 (D.5 v0.2 Task 18, Azure half; per-cloud `[estimate]`, honest; docs-only).
