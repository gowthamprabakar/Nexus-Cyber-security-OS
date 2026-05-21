# Example 2 — A/B comparison with byte-equal acceptance

Operator command (testing whether a proposed `synthesis` NLAH change is behavior-preserving under stub-LLM mode):

```sh
meta-harness ab-compare synthesis \
  --variant-a packages/agents/synthesis/src/synthesis/nlah \
  --variant-b packages/agents/synthesis/src/synthesis/nlah/.proposed
```

What A.4 does this run:

1. The CLI builds an `ABCompareRequest` with `agent_id="synthesis"`, the two `Path` objects, and the operator's `customer_id` + `run_id`.
2. **AB_COMPARE** loads the synthesis agent's bundled eval cases once.
3. **Variant A pass.** `nlah_override(/.../synthesis/nlah)` context patches `charter.nlah_loader.default_nlah_dir` to redirect. `run_suite` runs the synthesis runner under the canonical NLAH and produces a `SuiteResult` with 10/10 cases passing.
4. **Variant B pass.** `nlah_override(/.../synthesis/nlah/.proposed)` context. Same suite, this time the proposed NLAH. The runner picks up the proposed persona changes (a tightened reviewer prompt). `SuiteResult` shows 10/10 cases passing — pass rate identical.
5. **Diff.** `compare_results` walks each `EvalResult` pair. Per-case, the serialized `RunOutcome` payload (case_id + runner + passed + failure_reason + actuals) is identical for 9 of 10 cases. Case `case_07_classifier_label_drift` has a different `actuals.review_retries` value (the tightened prompt now resolves on the first pass instead of needing the retry) — `byte_equal=False` for that one case.
6. **Top-level `byte_equal`.** Because at least one per-case delta has `byte_equal=False`, the top-level flag is `False`. This is the **WI-3 signal** — under stub-LLM mode + identical NLAH the flag MUST be True, so a `False` either indicates a real behavioral change (here: the prompt tightening removed a retry round) or a hidden non-determinism source.
7. **HANDOFF** writes the report markdown showing the A/B summary + persists one `ab_comparison_result` entity.

Output fragment from the report's "A/B comparison" section:

```markdown
## A/B comparison

- **Agent:** `synthesis`
- **Variant A:** `packages/agents/synthesis/src/synthesis/nlah` — pass rate 100.0%
- **Variant B:** `packages/agents/synthesis/src/synthesis/nlah/.proposed` — pass rate 100.0%
- **Byte-equal across variants (WI-3):** ✗ divergent

| Case                             | Variant A | Variant B | Byte-equal |
| -------------------------------- | --------- | --------- | ---------- |
| `case_01_clean_batch`            | ✓ pass    | ✓ pass    | ✓          |
| ...                              | ...       | ...       | ...        |
| `case_07_classifier_label_drift` | ✓ pass    | ✓ pass    | ✗          |
| ...                              | ...       | ...       | ...        |
```

The operator now knows the proposed change is **pass-rate-preserving but behavior-changing on one case** — exactly the signal an A/B compare is designed to surface.
