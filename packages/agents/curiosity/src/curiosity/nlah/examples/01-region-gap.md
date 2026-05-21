# Example 01 — region-gap (clean happy-path run)

This is the operator-facing flow for a typical D.12 run when a single coverage gap is detected.

## Stage 1 INGEST — read aggregate state

The driver reads `aws_account_region` and `finding_aggregate` entities for the active `customer_id` from `SemanticStore`:

```text
SiblingState(
    regions=(
        RegionState(region="us-east-1", asset_count=120, days_since_last_finding=2, last_finding_severity="medium"),
        RegionState(region="eu-west-3", asset_count=42, days_since_last_finding=-1, last_finding_severity=None),
    ),
    total_assets=162,
    total_findings_30d=1,
)
```

`eu-west-3` has 42 assets but `-1` (sentinel for "never scanned") for `days_since_last_finding` — the strongest gap signal.

## Stage 2 DETECT — region-gap detector

```text
gaps = (
    CoverageGap(region="eu-west-3", asset_count=42, days_since_last_finding=0, severity_hint="medium"),
)
```

`us-east-1` is filtered out (recent finding within the 30-day window). `eu-west-3` qualifies on the never-scanned path; `days_since_last_finding` is normalised to `0` for the schema's `ge=0` constraint.

## Stage 3 HYPOTHESIZE — single LLM call

The LLM receives the gap list + the bundled `hypothesis.md` prompt. It returns:

```json
{
  "hypotheses": [
    {
      "statement": "The eu-west-3 region has 42 assets but no findings recorded in any scan window.",
      "rationale": "F.3 Cloud Posture and D.5 Data Security have not surfaced any findings for assets in eu-west-3, despite an inventory of 42 entities. This is consistent with a coverage gap rather than clean posture. Recommend running D.5 across the region's S3 buckets to establish a baseline; if D.5 returns clean, also schedule D.7 Investigation against any flagged finding from the run.",
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

## Stage 4 REVIEW — Q6 substring guard

The hypothesis text + rationale + probe directive carry no classifier-shaped substrings. The reviewer returns:

```text
ReviewVerdict(passed=True, retry_hint="", violations=[])
```

## Stages 5–6 PERSIST + PUBLISH

The driver mints a fresh ULID claim_id and backfills `probe_directive.rationale_ref`. Then:

- **PERSIST**: `HypothesisEntity` upserted to `SemanticStore` with `entity_type="hypothesis"`, `external_id="<customer_id>:<run_id>:0"`.
- **PUBLISH**: `CuriosityClaim` published on `claims.tenant.<customer_id>.agent.curiosity`. Payload is the `nexus_claim` JSON envelope.

## Stage 7 HANDOFF — workspace artifacts

```markdown
# Curiosity Hypotheses — <customer_id>

_Scan window: 2026-05-21T08:00:00+00:00 → 2026-05-21T08:00:08+00:00_
_Run ID: `01J7M3X9Z1K8RPVQNH2T8DBHFZ`_
_Total claims: 1_
_Gaps addressed: 1_
_Review retries: 0_

## Hypothesis 1 — `01J7M3X9Z1K8RPVQNH2T8DCMNO`

The eu-west-3 region has 42 assets but no findings recorded in any scan window.

F.3 Cloud Posture and D.5 Data Security have not surfaced any findings for assets in eu-west-3, despite an inventory of 42 entities. This is consistent with a coverage gap rather than clean posture. Recommend running D.5 across the region's S3 buckets to establish a baseline; if D.5 returns clean, also schedule D.7 Investigation against any flagged finding from the run.

**Probe directive:** data_security → `scan` on `arn:aws:s3:::eu-west-3-*`

_Cited gap: region=`eu-west-3`, asset_count=42, days_since_last_finding=0, severity_hint=`medium`_
```

The `probe_directives.json` companion carries the same directive in structured form for downstream D.7/D.5/D.8 v0.2 consumer integration.
