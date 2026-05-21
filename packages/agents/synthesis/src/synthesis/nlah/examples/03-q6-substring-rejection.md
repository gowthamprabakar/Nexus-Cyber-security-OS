# Example 03 — Q6 substring rejection + retry

This example walks through the Q6 reviewer-retry loop, the load-bearing WI-2 acceptance gate. It shows how a leaky first-pass narration triggers the deterministic Q6 substring guard, which forces a retry with a `[Q6 RETRY]` banner, after which the second pass renders the same content categorically.

## Pass 1 — narrator leaks a classifier-shaped substring

The LLM, despite seeing only the classifier label `ssn` in the context bundle, hallucinates a plausible-looking US SSN in the prose:

```markdown
## Storage exposure

The `arn:aws:s3:::contoso-public-uploads` bucket contains objects classified as PII. For example, one object contained the SSN `123-45-6789` exposed to public-read ACLs.
```

The reviewer's deterministic regex pass detects the SSN-shape substring and returns:

```python
ReviewVerdict(
    passed=False,
    retry_hint="q6_violation",
    violations=[
        "section 'Storage exposure' body contains classifier-shaped substring (ssn)"
    ],
)
```

Note the violation string names the classifier label (`ssn`), NEVER the matched substring itself — the Q6 invariant applies to the reviewer's own audit output too.

## Pass 2 — narrator re-runs with the Q6 retry banner

The driver re-invokes `narrate()` with `q6_violation_retry_hint=True`. Each per-section prompt now carries this appended banner:

```
[Q6 RETRY] A previous narration attempt produced classifier-shaped substrings
(SSN / credit-card / AWS-access-key / JWT). DO NOT produce such substrings
again. Refer to data categorically by classifier label, never by value.
```

The LLM produces a clean retry:

```markdown
## Storage exposure

The `arn:aws:s3:::contoso-public-uploads` bucket contains objects classified as containing data of type `ssn`. The classifier label is reported here without producing the matched substring; auditors should refer to the F.3 finding `CSPM-AWS-S3-001-contoso-public-uploads` for the underlying evidence.
```

The reviewer passes the retry. The final `SynthesisReport` carries `review_retries=1`, and the audit chain records both the rejection and the successful retry.

## Pass 3 (hypothetical) — Q6 budget exhausted

If the second pass also leaked (which is exceedingly unlikely with the retry banner), the driver hits the `Q6_RETRY_BUDGET=1` cap, accepts the degraded draft, logs a warning, and surfaces the violations in the audit log. The operator can then decide whether to re-run or accept.
