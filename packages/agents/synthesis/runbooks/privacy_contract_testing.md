# Runbook — Privacy Contract + Invariant Testing (synthesis v0.2)

The three code-level LLM-agent invariants (the institutional template for D.7/D.12/A.4):

- **`privacy.categorical.assert_categorical_only(chunk)`** (WI-Y8/Q4) — raises on plaintext
  PII/PAN/secrets in a narrative; refer by classification LABEL (`[SSN]`) only.
- **`retry.bounded.assert_bounded_retry(n)`** (WI-Y10/H5) — raises if attempts exceed 2
  (initial + 1 retry); accept the degraded draft on exhaustion.
- **`validation.hallucination_guard.assert_findings_cited(narrative, source_ids)`** (WI-Y13) —
  raises if the narrative cites a backticked finding id absent from the source set.

Test PII-bearing inputs through the pipeline; the categorical guard must block any plaintext
leak, and the hallucination guard must block a fabricated finding id before emission.
