# Example 01 — executive-summary shape (clean run)

This is the executive_summary.md output shape for a clean, low-finding-count run.

```markdown
# Executive Summary — acme

_Scan window: 2026-05-21T08:00:00+00:00 → 2026-05-21T08:05:00+00:00_
_Run ID: `01J7M3X9Z1K8RPVQNH2T8DBHFZ`_

The 2026-05-21 morning scan window surfaced two high-severity findings concentrated in the IAM posture: one root-account-MFA gap (CIS 1.10) and one S3 bucket exposed to the public internet (CIS 2.1.1). No critical-severity findings were detected. The compliance posture is intact at CIS Level 1 with the exception of the noted IAM control; address the root MFA gap before the next quarter's audit window.

## Key Metrics

- **total_findings**: 2
- **critical**: 0
- **high**: 2
- **top_failing_control**: 1.10
```

Note the shape contract: H1 with customer ID, scan window metadata, the C-suite paragraph (60–200 words), and a `## Key Metrics` block as a bulleted list. The paragraph leads with the headline finding, names the affected control IDs, and ends with a directional statement.
