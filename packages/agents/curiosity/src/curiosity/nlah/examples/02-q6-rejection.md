# Example 02 — Q6 substring rejection + retry

This walks through the Q6 reviewer-retry loop, the load-bearing WI-2 acceptance gate. It shows how a leaky first-pass hypothesis triggers the deterministic Q6 substring guard, which forces a retry with a `[Q6 RETRY]` banner, after which the second pass renders the same content categorically.

## Pass 1 — LLM leaks a classifier-shaped substring

Despite seeing only classifier _labels_ in the context (no matched values), the LLM hallucinates a plausible-looking SSN in the rationale:

```json
{
  "hypotheses": [
    {
      "statement": "The eu-west-3 buckets likely contain unscanned PII.",
      "rationale": "Buckets in eu-west-3 may contain SSN values like 123-45-6789 in plaintext. Recommend a classification scan to confirm.",
      "probe_directive": {
        "target_agent": "data_security",
        "target_resource_arn": "arn:aws:s3:::eu-west-3-*",
        "action": "scan",
        "rationale_ref": ""
      },
      "cited_gap": {
        "region": "eu-west-3",
        "asset_count": 42,
        "days_since_last_finding": 0,
        "severity_hint": "medium"
      }
    }
  ]
}
```

The reviewer's deterministic regex pass detects the SSN-shape substring:

```text
ReviewVerdict(
    passed=False,
    retry_hint="q6_violation",
    violations=[
        "hypothesis index 0 rationale contains classifier-shaped substring (ssn)"
    ],
)
```

The violation string names the classifier label (`ssn`), **NEVER** the matched substring — the Q6 invariant applies to the reviewer's own audit output too.

## Pass 2 — driver re-runs hypothesize with the Q6 retry banner

The driver re-invokes `hypothesize()` with `q6_violation_retry_hint=True`. The hypothesizer appends this banner to the user-prompt JSON:

```text
[Q6 RETRY] A previous hypothesis attempt produced classifier-shaped
substrings (SSN / credit-card / AWS-access-key / JWT). DO NOT produce
such substrings again. Refer to data categorically by classifier label,
never by value.
```

The LLM returns a clean retry:

```json
{
  "hypotheses": [
    {
      "statement": "The eu-west-3 buckets likely contain unscanned PII.",
      "rationale": "Buckets in eu-west-3 may contain data classified as `ssn`. The classifier label is reported categorically; refer to the source finding for any underlying evidence once D.5 has run. Recommend a classification scan across the region's S3 buckets.",
      "probe_directive": {
        "target_agent": "data_security",
        "target_resource_arn": "arn:aws:s3:::eu-west-3-*",
        "action": "scan",
        "rationale_ref": ""
      },
      "cited_gap": {
        "region": "eu-west-3",
        "asset_count": 42,
        "days_since_last_finding": 0,
        "severity_hint": "medium"
      }
    }
  ]
}
```

The reviewer passes the retry. The final `CuriosityReport` carries `review_retries=1`, and the audit chain records both the rejection and the successful retry.

## Pass 3 (hypothetical) — Q6 budget exhausted

If the second pass also leaked (exceedingly unlikely with the retry banner), the driver hits the `_Q6_RETRY_BUDGET=1` cap, accepts the degraded draft, logs a warning, and surfaces the violations in the audit log. The operator can then decide whether to re-run or accept.

The workspace markdown is still emitted (degraded but legal output). The published `claims.>` payload still carries the leaky rationale — downstream consumers see what was emitted, including the violations for their own audit.
