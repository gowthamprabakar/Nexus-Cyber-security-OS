# Detector red-team findings — 2026-06-29

Adversarially attacked our own detectors (not "tests that confirm green" — tests designed to
**break** them). Every item below is a real probe result, not a theory. Fixed items shipped with a
permanent red-team regression test; open items are tracked here, honestly, rather than hidden behind
a green bank.

## Fixed this session

| #   | Flaw                                                                                | Was                                                                      | Now                                                     | Where                             |
| --- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------- | --------------------------------- |
| 1   | **SSH/RSA private keys (PEM)** classified                                           | MISSED entirely — a public bucket leaking `id_rsa` produced **0 alerts** | `private_key` + fires `public_secret`                   | classifier + `_SECRET_DATA_TYPES` |
| 2   | **GitHub / Google / Stripe / Slack tokens**                                         | missed (Slack mis-labeled `credit_card`)                                 | dedicated labels, alert fires                           | classifier `patterns.py`          |
| 3   | **AWS temporary creds** (`ASIA…`)                                                   | missed (regex was `AKIA`-only)                                           | caught                                                  | access-key regex                  |
| 4   | **Encoding evasion** — hex, base32, double-base64, base64+gzip combos, url-encoding | missed (peeled exactly one gzip OR base64 layer)                         | recursive peeler, ≤3 layers, gzip/base64/base32/hex/url | `classify_bytes`                  |

Two-layer lesson on #1: even after the classifier learned private keys, the **alert allowlist**
(`kg_query._SECRET_DATA_TYPES`) still recognized only 3 credential types — so the classified key
never surfaced. A flaw can hide one layer deeper than the obvious one.

## Open — tracked, not yet fixed

| #   | Flaw                                                                                                                                                                                                                                  | Severity    | Why deferred                                                                                                                                                                 |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5   | **IAM privilege-escalation methods** — `iam:CreatePolicyVersion`, `iam:PassRole`→service, `iam:AttachUserPolicy`, `lambda:CreateFunction`+PassRole, etc. (the classic ~20). Only full-admin (`*:*`) + assume-role chains are modeled. | **HIGH**    | A whole feature (cloudsplaining / PMapper class). A non-admin with `iam:CreatePolicyVersion` on an admin-attached policy escalates to admin and we'd see a normal principal. |
| 6   | **Policy logic inversion** — `NotAction` / `NotResource` `Allow`. The parser reads `"Action"`, which a `NotAction` statement lacks → an over-broad grant is invisible.                                                                | MEDIUM-HIGH | Correct handling = effective-permission resolution of inverted logic; interim fix is to _flag_ `NotAction:Allow` as over-broad.                                              |
| 7   | **Sampling needle-in-haystack** — object sampling (~1%) can miss a secret in 1 of N objects in a large bucket.                                                                                                                        | MEDIUM      | Inherent to sampling (recorded as `SampleBasis`); full-scan is cost/latency tradeoff.                                                                                        |
| 8   | **Secret in object metadata / key name** (not body) — only object bodies are sampled.                                                                                                                                                 | MEDIUM      | Needs a metadata/key-name scan pass.                                                                                                                                         |
| 9   | **Inline DB-connection password** (`postgres://user:pw@host`) — not flagged as a credential.                                                                                                                                          | LOW-MED     | Catching arbitrary inline passwords is high false-positive risk; documented in the red-team test.                                                                            |

## Checked and found SOUND (honest both ways)

- `AllUsers` **and** `AuthenticatedUsers` ACL grants → both treated as public. ✓
- IPv6 `::/0` in a security group → checked alongside `0.0.0.0/0`. ✓
- Block-Public-Access neutralizing a wildcard bucket policy → respected (no false positive). ✓
- Single-layer gzip / base64 secret → peeled. ✓
- Random/benign blobs through the new recursive peeler → stay `NONE` (no false positives). ✓

## The takeaway

The deep capability bank scored 1.000 — and was still blind to private keys, modern tokens, and
every non-trivial encoding, because it only tested what we thought of. **Adversarial probing is how
real coverage gaps surface.** Apply it to every detector, especially identity (#5 is the biggest
single gap in the product right now).
