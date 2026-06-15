# v0.3 / Phase D — A-3 deeper recon: native-CIS compliance consumption + k8s CIS bump (2026-06-15)

> **Status:** Recon findings (doc-only, NO code). Captures the grounded
> implementation plan + blockers for the two remaining A-3 items so the
> (accuracy-sensitive) implementation can be done fresh-context without fabrication.
> A-3 PR1 (#689 dual-shape Prowler OCSF + native CIS extraction) + PR2 (#693 CIS
> coverage artifact) already shipped; these are the deeper follow-ons.

## Item 1 — Compliance consumes native CIS by control_id (cross-agent)

**Goal.** Today the compliance `cloud_posture_correlator` maps a cloud-posture
finding to CIS controls ONLY via the YAML `source_mappings` index keyed by
`(source_agent, rule_id)` — so Prowler's hash-synthetic rule_ids never map. #689
made cloud-posture findings additionally carry Prowler's NATIVE CIS attribution in
`evidences[].cis_controls` (e.g. `["CIS-3.0:1.10"]`). A second attribution path
would let ANY Prowler finding map to CIS via its own emitted control — no manual
YAML expansion, no fabrication.

**Why it's non-trivial (verified in the correlator):**

- `_build_compliance_finding` is built around `IndexedMapping` (control_id +
  control_name + control_description + framework + per-mapping level/required +
  `source_rule_id`). It is constructed today ONLY from the YAML `source_mappings`
  (`build_control_index`).
- A native-CIS path needs to build a `ComplianceFinding` from a bare `control_id`
  (e.g. `"1.10"`) — which requires the **CisControl catalog by control_id**
  (name/description/level/required), NOT currently passed to the correlator (it
  only receives the `(agent,rule_id)`→mappings `ControlIndex`).
- So the change must: (a) thread a `control_id → CisControl` lookup into the
  correlator; (b) parse `"CIS-3.0:1.10"` → framework + control_id; (c) match the
  framework version (`CIS-3.0` ↔ the loaded `cis_aws_v3` v3.0.0) — skip on mismatch;
  (d) synthesize an `IndexedMapping` (or a parallel builder) with a native-source
  marker (`source_rule_id` = the Prowler check / "native_cis"); (e) **update the
  `test_cis_aws_wiring` drift-guard** (it currently asserts the wiring is only the
  hand-mapped set — a native path changes that surface).

**Accuracy note (the load-bearing constraint).** This path consumes Prowler's OWN
emitted control_ids and matches them to controls that ALREADY exist in
`cis_aws_v3.yaml`. It must **skip** any native control_id not present in the loaded
framework (never invent a control). De-dup against the YAML-mapped path so a
finding mapped both ways isn't double-counted.

**Effort/risk:** ~1-2 days; MEDIUM risk (touches the compliance correlation core +
its drift-guard). Fresh-context recommended. Substrate: agent-local (no
shared/charter).

## Item 2 — k8s-posture CIS v1.8 → v2.0 bump + manifest-rule expansion

**Two separable sub-parts with very different risk:**

- **(2a) manifest-rule expansion — ACCURACY-SAFE, do first.** Adding k8s manifest
  detectors (missing NetworkPolicy, seccomp/AppArmor unset, missing
  PodDisruptionBudget, resource-limit enforcement, etc.) is well-known k8s security
  hardening — NOT CIS-numbered, so no fabrication risk. Single-agent, additive.
- **(2b) CIS v1.8 → v2.0 control bump — ACCURACY-SENSITIVE, needs a source.**
  `k8s_posture/cis/benchmark.py` ships 16 CIS K8s **v1.8** controls. Bumping to
  **v2.0** requires the authoritative CIS Kubernetes Benchmark v2.0 control
  IDs/titles. **Do NOT hand-transcribe from memory** (the compliance Q2 "never
  fabricate CIS" lesson). Fetch from an authoritative source first (context7
  `kube-bench`, or the official CIS benchmark) and reconcile control-by-control.

**Effort/risk:** 2a ~1 day LOW; 2b ~1-2 days MEDIUM (gated on authoritative data).
Substrate: agent-local.

## Sequencing note

B-1 is **sequential per-PR review**; with B-1 PR4 (#695) open, no further B-1 PR
should be queued until it merges. These A-3 items are **self-merge** (no operator
gate) and can fire in parallel with the B-1 review track whenever taken up.

## Recommendation

1. **k8s 2a (manifest rules)** first — accuracy-safe, single-agent, clean self-merge.
2. **Compliance native-CIS consumption (Item 1)** next — fresh-context, with the
   IndexedMapping/catalog threading + drift-guard update above.
3. **k8s 2b (CIS v2.0)** last — only after fetching authoritative v2.0 control data.

## References

- A-3 recon — `v0-3-a-3-recon-2026-06-14.md`; A-3 PR1 #689 (dual-shape + native CIS);
  A-3 PR2 #693 (coverage artifact).
- Correlator — `compliance/correlators/cloud_posture_correlator.py`
  (`_build_compliance_finding`) + `control_index.py` (`IndexedMapping`,
  `build_control_index`); drift-guard `test_cis_aws_wiring.py`.
- k8s controls — `k8s_posture/cis/benchmark.py` (16 × CIS v1.8).
