# Data Security Agent — Tools Reference

Nine surfaces, grouped by stage. Two readers + one F.3-correlation reader are async-safe (per ADR-005) so the agent driver can fan them out via `asyncio.TaskGroup`; the classifier, 4 detectors, scorer, and summarizer are pure functions.

## Stage 1: INGEST

### `read_s3_inventory(*, path: Path) -> tuple[BucketInventory, ...]`

Async parser for operator-staged S3 bucket inventory JSON. Supports two top-level shapes: canonical `{"buckets": [...]}` and bare list. Per-bucket validation failures are dropped silently (forgiving — mirrors F.3 / multi-cloud-posture).

The bucket model carries:

- `name` (3-63 char S3 bucket name), `region`, `account_id` (12-digit AWS account ID).
- `acl.grants_all_users` + `acl.grants_authenticated_users` — permission string lists.
- `public_access_block` — 4 BPA flags (defaults all True).
- `encryption.algorithm` — one of `NONE` / `AES256` / `aws:kms` / `aws:kms:dsse`.
- `policy_json` — raw bucket-policy JSON string (or None).
- `tags` — dict of bucket-level tags; `Sensitivity` key drives the sensitive-location detector.

### `read_s3_objects(*, path: Path) -> tuple[ObjectSample, ...]`

Async parser for operator-staged S3 object-sample JSON. Each sample carries `bucket`, `key`, and `content_sample_b64` (base64-encoded bytes, capped at 16 KiB per `MAX_SAMPLE_BYTES`). Bad base64 / oversized samples / missing fields → drop silently. `ObjectSample.decoded_text()` returns the sample as UTF-8 text with replacement on invalid bytes (binary samples don't crash; they just don't match any classifier pattern).

**Q6 reminder.** Sample bytes leave this reader as part of the returned `ObjectSample` tuple. The agent driver passes them to `classify()` and immediately discards the reference. The reader itself does NOT log or persist the bytes.

## Stage 2: CLASSIFY

### `classify(text: str) -> ClassifierLabel`

The privacy-contract-load-bearing API. Returns one of 8 enum values (7 PII labels + NONE). **NEVER returns the matched substring.** Match precedence (most specific first):

1. **AWS access key** — `AKIA[0-9A-Z]{16}`.
2. **JWT** — 3-segment base64url with `eyJ` header prefix.
3. **SSN (US)** — `\d{3}-\d{2}-\d{4}`.
4. **Credit card** — 13-19 digits passing the Luhn check.
5. **Email** — RFC-5322-ish.
6. **US phone** — area code + 7 digits, optional country code.
7. **Generic API token** — 40+ char string adjacent to `secret:` / `token:` / `api_key:`.
8. `ClassifierLabel.NONE` — no match.

Pure function. Stateless. Deterministic. Q6 violations caught at the signature gate via `test_q6_privacy_contract_signature_returns_label_only`.

## Stage 3: DETECT (4 pure functions)

### `detect_public_bucket(bucket, *, classifier_hits, envelope, detected_at, sequence) -> list[CloudPostureFinding]`

Flags buckets with public ACL grants or BPA gaps. Severity HIGH; CRITICAL with classifier hit. Finding-id: `CSPM-AWS-PUBLIC-NNN-<slug>`.

### `detect_unencrypted(bucket, *, classifier_hits, envelope, detected_at, sequence) -> list[CloudPostureFinding]`

Flags buckets with `encryption.algorithm == "NONE"`. Severity MEDIUM; HIGH with classifier hit. Finding-id: `CSPM-AWS-UNENC-NNN-<slug>`.

### `detect_sensitive_location(bucket, *, classifier_hits, envelope, detected_at, sequence, trusted_tag_value="Restricted") -> list[CloudPostureFinding]`

Tag-drift detector. Fires when classifier-hit AND bucket is not tagged `Sensitivity=Restricted`. Severity HIGH (single level — classifier hit IS the trigger). Operator override via `trusted_tag_value`. Finding-id: `CSPM-AWS-SENSLOC-NNN-<slug>`.

### `detect_oversharing_iam(bucket, *, classifier_hits, envelope, detected_at, sequence) -> list[CloudPostureFinding]`

Parses bucket-policy JSON for cross-account / wildcard read grants without MFA / IP / VPCE / OrgID guards. Same-account principals and Service principals not flagged. Severity MEDIUM; HIGH with classifier hit. Finding-id: `CSPM-AWS-OVERSHARE-NNN-<slug>`.

## Stage 4: CORRELATE

### `read_f3_findings(workspace_path: Path) -> tuple[dict, ...]`

Async reader for sibling F.3 cloud-posture workspace's `findings.json`. Forgiving — missing file / malformed JSON / unrecognised shape → empty tuple, no exception. Supports canonical `FindingsReport` (`{"findings": [...]}`) + bare-list shapes.

### `correlate_with_f3(d5_findings, f3_findings) -> CorrelationResult`

Pure function. Builds an ARN → list[f3_finding_id] index, then matches each D.5 finding's bucket ARN to F.3 findings on the same ARN. Returns `CorrelationResult(matches={d5_finding_id: [f3_finding_id, ...]}, raw_f3_finding_count=N)`.

## Stage 5: SCORE

### `apply_correlation_uplift(findings, correlation) -> tuple[CloudPostureFinding, ...]`

Pure function. For each finding with `correlation.matches_for(id)` non-empty, uplifts severity one level (cap CRITICAL) and appends a `correlation_uplift` evidence entry. Input findings not mutated.

Uplift order: INFO → LOW → MEDIUM → HIGH → CRITICAL → CRITICAL.

## Stage 6: SUMMARIZE

### `render_summary(findings, *, run_id) -> str`

Deterministic markdown render. Pure function. Layout: header (run_id + total + severity breakdown) → per-detector breakdown (alphabetical) → CRITICAL pinned above HIGH/MEDIUM/LOW/INFO. Findings sorted by finding_id within each severity section.

**Q6 render-layer assert (load-bearing).** After rendering, runs `classify()` over the full markdown. If any `ClassifierLabel != NONE` returns, raises `SummarizerQ6Violation` — meaning a prior stage leaked classifier-matched content into a finding's title / desc / evidence.
