# Example 2 — DGA-shaped DNS query flagged

**Input:** 24 hours of Route 53 Resolver Query Logs for `vpc-prod-east-1`.

**Observation:** Host 10.0.5.17 queries `xkfqpzwvxghmpls.tld` once every 5 minutes. The second-level label `xkfqpzwvxghmpls` has Shannon entropy 4.21 (random-looking) and a bigram score of 0.00 (no common English bigrams).

**Detection:**

```yaml
finding_type: network_dga
severity: HIGH # entropy >= 4.0 AND bigram_score <= 0.05
title: DGA-shaped DNS query: xkfqpzwvxghmpls.tld
detector_id: dga@0.1.0
src_ip: 10.0.5.17
evidence:
  query_name: xkfqpzwvxghmpls.tld
  second_level_label: xkfqpzwvxghmpls
  entropy: 4.2103
  bigram_score: 0.0
  query_type: A
```

**Dedupe:** the host queries the same name 288 times in the window (every 5 min × 24 h); detector emits **one** finding (deduplicated by `(src_ip, query_name)`).

**ENRICH (no match):** the random label doesn't match any `known_bad_domains` suffix in the bundled intel. Severity stays HIGH.

**Suffix allowlist check (suppressed):** if instead the query had been `xkfqpzwvxghmpls.cloudfront.net`, the detector would never have evaluated it — the `.cloudfront.net` suffix is on the bundled allowlist (CloudFront edge nodes legitimately use high-entropy labels).

**Markdown report pin:**

> **HIGH DGA-shaped query detected.** Host `10.0.5.17` is querying `xkfqpzwvxghmpls.tld` every 5 minutes (entropy 4.21, bigram-score 0.0). This pattern is consistent with domain-generation-algorithm output. **Note:** v0.1 ships an entropy/bigram heuristic; a Phase-1c ML model will improve precision.

**Limits acknowledged in v0.1** (the README documents these):

- `stackoverflow.com`-shape labels can rarely false-positive due to consonant-heavy bigrams.
- The bundled suffix allowlist is a snapshot; Phase 1c integrates a live allowlist API.
- We do NOT yet attempt to fetch the resolved IP and chain into beacon detection — that's a Phase 1c lift.
