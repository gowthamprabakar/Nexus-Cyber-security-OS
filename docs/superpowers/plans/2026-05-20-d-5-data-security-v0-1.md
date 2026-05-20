# D.5 — Data Security Agent (DSPM) v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Pause for review after each numbered task.

**Goal:** Ship the **Data Security Agent** (`packages/agents/data-security/`) — the **first of the 7 unbuilt agents** under the [Path-B-breadth-first operating rule](../sketches/2026-05-20-agent-version-roadmaps.md) (2026-05-20) and the **eleventh under [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / **D.5 Data Security**). Lifts platform coverage from **CSPM-only** into **DSPM** — the first agent that discovers + classifies sensitive data at rest.

**Scope (v0.1, Option A — locked 2026-05-20).** AWS S3 only, offline-mode (boto3 inventory snapshots staged by operator to filesystem). 4 deterministic detector rules (`s3_bucket_public`, `s3_bucket_unencrypted`, `s3_object_sensitive_in_untrusted_location`, `s3_oversharing_iam`). Agent-local PII/sensitive-data classifier (regex + Luhn). F.3 cloud-posture cross-correlation (annotate D.5 findings when F.3 already flagged the bucket). OCSF v1.3 Compliance Finding `class_uid 2003` — **identical wire shape to F.3 / multi-cloud-posture / k8s-posture** with `finding_info.types[0]="data_security"` discriminator. Deterministic (no LLM in loop). Single-tenant (`semantic_store=None` opt-in default). v0.1 ships eval-only; live-lane CI workflow deferred to v0.2.

**Strategic role.** First "detect data" agent. **Breadth-first ship under the Path-B operating rule** — adds the DSPM shape to the platform's agent inventory before any v0.2+ expansion on the 10 already-shipped agents. Closest existing pattern is F.3 cloud-posture (same OCSF wire shape, same offline-mode pattern, same deterministic-in-v0.1 stance). Zero charter-level substrate work — the agent replicates the F.3 template with three new pieces: (a) **agent-local classifier** under `classifiers/patterns.py` (regex + Luhn; promotion to `charter.data_classification` deferred per ADR-007 3rd-consumer hoist rule); (b) **4 detector rules** as separate pure-function modules; (c) **F.3 cross-correlation pass** (operator-pinned sibling workspace read, mirrors D.7's pattern). v0.1 demo surface: "data-classification across AWS S3 substrates in one OCSF report; toxic combinations cross-correlated to F.3 cloud-posture findings."

**Q1 (resolve up-front).** Schema reuse — share F.3's `cloud_posture.schemas` or fork into a per-agent shape?

**Resolution: re-export F.3's `class_uid 2003 Compliance Finding`** with `finding_info.types[0]="data_security"` discriminator + add a `DataSecurityFindingType` enum (4 buckets: `s3_bucket_public` / `s3_bucket_unencrypted` / `s3_object_sensitive_in_untrusted_location` / `s3_oversharing_iam`) + a `ClassifierLabel` enum (SSN / CREDIT_CARD / AWS_ACCESS_KEY / JWT / EMAIL / PHONE / GENERIC_API_TOKEN / NONE) on the `finding_info` dict. Same precedent as multi-cloud-posture + k8s-posture re-exporting F.3 schemas (ADR-007 v1.2 first-of-platform pattern). Unlocks D.7 / Meta-Harness downstream consumers that already filter on `class_uid 2003`.

**Q2 (resolve up-front).** Live boto3 calls or offline filesystem fixtures in v0.1?

**Resolution: offline filesystem snapshots only.** Operator stages two JSON snapshots per scan: an S3 bucket-inventory dump (output of `aws s3api list-buckets` + per-bucket `get-bucket-policy` / `get-public-access-block` / `get-bucket-encryption` / `get-bucket-acl`) and an object-sample dump (object keys + first ~16 KiB of content for classification). Mirrors F.3 LocalStack-pattern + multi-cloud-posture's offline mode. Live boto3 SDK calls deferred to D.5 v0.2 (same shim-behind-reader pattern as F.3).

**Q3 (resolve up-front).** Classifier — agent-local or hoisted to `charter.data_classification` substrate?

**Resolution: agent-local under `data_security/classifiers/`.** Per the 2026-05-20 remaining-agents sketch §1: "agent-local for v0.1; promote to charter substrate only if D.6 Compliance or D.12 Curiosity end up needing the same classifier." ADR-007 3rd-consumer hoist rule applies — D.5 is the 1st consumer; promotion candidate when D.6 Compliance v0.2 (GDPR/CCPA framework controls reading DSPM findings) or D.12 Curiosity v0.1 appears.

**Q4 (resolve up-front).** Cross-correlation with F.3 cloud-posture findings — automatic discovery or operator-pinned?

**Resolution: operator-pinned via `--cloud-posture-workspace` flag.** Mirrors D.7 Investigation's sibling-workspace read pattern. When the flag is present and the path exists, D.5 reads `findings.json` from that workspace and, for each D.5 finding emitted, scans for F.3 findings on the same bucket ARN. Match → annotates D.5 finding with a `data_security_correlation` field listing the matching F.3 finding-IDs + a `severity_uplift` flag (the rule: if D.5 finds public-bucket + F.3 finds the same bucket with a CSPM-violating tag, D.5's severity uplifts one level, capped at CRITICAL). Flag absent → D.5 runs standalone (still emits findings; no correlation). v0.1 does NOT autodiscover sibling workspaces.

**Q5 (resolve up-front).** Tenancy — single-tenant or multi-tenant in v0.1?

**Resolution: single-tenant (`semantic_store=None` opt-in default).** Per the Path-B operating rule §11.1: SET LOCAL `$1` tenant-RLS bug NOT a v0.1 blocker; multi-tenant production blocks on the future tenant-RLS substrate-fix plan. D.5 v0.1 writes finding-artifacts to the workspace filesystem only; no SemanticStore writes (no entity dedup needed in v0.1 — eval cases are file-based, no cross-run state). v0.2 may introduce SemanticStore writes when classifier-cache becomes valuable; that's the future plan's decision, not this one.

**Q6 (resolve up-front).** Privacy contract — what does "never log values" mean concretely?

**Resolution.** Per PRD §7.1.4 lines 957–966, D.5 enforces a hard privacy contract: **classifier outputs label only, never the matched substring**. The classifier API is `classify(text: str) -> ClassifierLabel` — returns a label enum, never the matched character span. Detector logs carry `(bucket, object_key, label)` triples, never `(bucket, object_key, label, matched_text)`. Eval cases assert that classifier-matched substrings never appear in `findings.json` or `report.md` (10 acceptance cases include an explicit "no-PII-leak" probe). This is **not optional** — operators rely on it for compliance; violation is a P0 bug.

---

## Architecture

```
ExecutionContract (signed)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│ Data Security Agent driver                                       │
│                                                                  │
│  Stage 1: INGEST        — 2 feeds concurrent via TaskGroup       │
│  Stage 2: CLASSIFY      — classifier over object-key samples     │
│  Stage 3: DETECT        — 4 pure-function detectors              │
│  Stage 4: CORRELATE     — optional F.3 sibling-workspace read    │
│  Stage 5: SCORE         — deterministic severity per detector    │
│  Stage 6: SUMMARIZE     — per-detector + per-severity sections   │
│  Stage 7: HANDOFF       — emit findings.json + report.md         │
└─────────┬────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│ Tools (per-stage)                                                │
│  read_s3_inventory      ─→ S3 bucket-inventory JSON (filesystem) │
│  read_s3_objects        ─→ S3 object-sample JSON (filesystem)    │
│  classify               ─→ regex + Luhn, ClassifierLabel enum    │
│  detect_public_bucket   ─→ ACL / Block Public Access analysis    │
│  detect_unencrypted     ─→ default-SSE absence                   │
│  detect_sensitive_loc   ─→ classifier-hit × untrusted bucket tag │
│  detect_oversharing     ─→ wildcard/cross-account IAM grants     │
│  read_f3_findings       ─→ sibling workspace (optional)          │
│  render_summary         ─→ per-detector + per-severity pinned    │
└──────────────────────────────────────────────────────────────────┘
```

**Tech stack.** Python 3.12 · BSL 1.1 · OCSF v1.3 Compliance Finding (`class_uid 2003`, `types[0]="data_security"` discriminator) · pydantic 2.9 · click 8 · `charter.llm_adapter` (ADR-007 v1.1; plumbed but never called) · `charter.nlah_loader` (ADR-007 v1.2). Re-exports F.3's `cloud_posture.schemas` for the OCSF Compliance Finding wire shape. No external network dependencies in v0.1.

**Depends on:**

- F.1 charter — standard budget caps; no extensions needed (D.5 is not always-on, not sub-agent-spawning).
- F.3 cloud-posture — re-exports `class_uid 2003 Compliance Finding` schema; reuses `Severity`, `AffectedResource`, `build_finding`, `FindingsReport`. No code duplication.
- F.4 control-plane — tenant context propagates through the contract; per-tenant cred-store integration deferred to v0.2.
- F.5 memory engines — `EpisodicStore` for per-run persistence (optional, v0.1 not invoked).
- F.6 Audit Agent — every D.5 run emits an audit chain via `charter.audit.AuditLog` (8 events: `agent_started` → `ingest_completed` → `classify_completed` → `detect_completed` → `correlate_completed` → `scored` → `summary_written` → `findings_published`).
- ADR-007 v1.1 + v1.2 — reference NLAH template. D.5 is the **11th** agent under it. v1.3 (always-on) opt-out; v1.4 (sub-agent spawning) not consumed.

**Defers (D.5 v0.2 / v0.3 / v0.4 / v0.5+, per the [2026-05-20 version-roadmap](../sketches/2026-05-20-agent-version-roadmaps.md#11-d5-data-security--dspm-operator-id-conflicts-with-multi-cloud-postures-self-claim)):**

- **RDS + DynamoDB scanning** (relational + key-value databases) — D.5 v0.3.
- **Live boto3 SDK calls** — D.5 v0.2.
- **Classifier expansion** (date-of-birth, addresses, healthcare IDs) + AWS Macie cross-validation — D.5 v0.2.
- **Azure Blob + Azure SQL** + **GCP Cloud Storage + BigQuery** — D.5 v0.4 (multi-cloud DSPM).
- **Snowflake + EFS + Kinesis** — D.5 v0.5+.
- **Bedrock / Vertex training-data forensics** — D.5 v0.5+ (blocks on Phase-2 AI-Security substrate).
- **Presidio custom classifier engine** — D.5 v0.5+ (replaces agent-local regex when classifier complexity outgrows it).
- **Toxic-combination detection** cross-correlating D.6 Compliance / F.3 — D.5 v0.5+ (full PRD §7.1.4 surface).
- **Multi-tenant production** — blocks on SET LOCAL `$1` fix (future tenant-RLS substrate plan; NOT this plan).
- **SemanticStore writes** (classifier cache, entity dedup) — D.5 v0.2 + decision.
- **F.7 fabric emission** — deferred until F.7 v0.3+ covers `findings.>` for non-D.7 producers.
- **AI training-data exposure detection** — Phase 2 per build-roadmap line 201.

**Reference template:** F.3 Cloud Posture Agent (closest match — same OCSF class, same compliance-finding shape, same offline-mode pattern, same single-cloud v0.1 stance). D.5 is structurally F.3 with: (a) classifier pass added (Stage 2); (b) detector-per-rule modules instead of one Prowler subprocess; (c) F.3-sibling-workspace cross-correlation pass (Stage 4); (d) shared schema with F.3 (re-export, not fork); (e) privacy-contract Q6 invariant (new; not present in any existing agent).

---

## Execution status

```
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16
```

| Task | Status | Commit | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---- | ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | ⬜     |        | Bootstrap — pyproject (BSL 1.1; deps on charter / shared / eval-framework / **nexus-cloud-posture** for F.3 schema re-export per Q1). py.typed + **init**. Smoke tests: ADR-007 v1.1 + v1.2 + F.1 audit log + F.3 schema re-export confirmation + 2 anti-pattern guards + 2 entry-point checks.                                                                                                                                                                         |
| 2    | ⬜     |        | `schemas.py` — re-exports F.3's `class_uid 2003 Compliance Finding` verbatim (Q1). Adds `DataSecurityFindingType` enum (4 detectors) + `ClassifierLabel` enum (7 labels + NONE).                                                                                                                                                                                                                                                                                        |
| 3    | ⬜     |        | `classifiers/patterns.py` — regex table + Luhn validator for credit-cards. Detectors: SSN (US 9-digit with hyphens), credit card (Luhn-validated), AWS access key (`AKIA[0-9A-Z]{16}`), JWT (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`), email, US phone, generic api-token (40+ char base64ish with `secret`/`token` adjacency hint). **`classify(text) -> ClassifierLabel` returns label only; matched substring NEVER returned** (Q6 privacy contract). |
| 4    | ⬜     |        | `tools/s3_inventory.py` — async reader for staged S3 bucket-inventory JSON (`{"buckets":[{name, region, acl, public_access_block, encryption, policy, tags},...]}`). Validates via pydantic; rejects malformed.                                                                                                                                                                                                                                                         |
| 5    | ⬜     |        | `tools/s3_objects.py` — async reader for staged S3 object-sample JSON (`{"objects":[{bucket, key, content_sample_b64},...]}`). Decodes base64; passes to classifier.                                                                                                                                                                                                                                                                                                    |
| 6    | ⬜     |        | `detectors/public_bucket.py` — flags `AllUsers`/`AuthenticatedUsers` ACL grants OR Block Public Access settings disabled. Severity HIGH (any public read) → CRITICAL (public read + classifier hit on objects in bucket). Pure function: `(BucketInventory) -> list[Finding]`. Tests.                                                                                                                                                                                   |
| 7    | ⬜     |        | `detectors/unencrypted.py` — flags missing default SSE-S3 / SSE-KMS. Severity MEDIUM → HIGH if classifier-sensitive content found inside. Pure function. Tests.                                                                                                                                                                                                                                                                                                         |
| 8    | ⬜     |        | `detectors/sensitive_location.py` — classifier-hit cross-referenced to bucket-tag policy. If `Sensitivity != "Restricted"` AND classifier hit → flag HIGH (sensitive data in untrusted location). Pure function. Tests.                                                                                                                                                                                                                                                 |
| 9    | ⬜     |        | `detectors/oversharing.py` — bucket policy parse; flags cross-account / wildcard `s3:Get*`/`s3:List*` without MFA / IP-condition guards. Severity MEDIUM → HIGH with classifier hit. Pure function. Tests.                                                                                                                                                                                                                                                              |
| 10   | ⬜     |        | NLAH bundle + 21-LOC shim. ADR-007 v1.2 conformance — D.5 is the 7th agent shipped natively against v1.2 (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture). README + tools.md + 2 examples (public-bucket-with-PII uplift; oversharing-IAM with classifier hit). LOC-budget test enforces ≤35 in shim.                                                                                                                                                  |
| 11   | ⬜     |        | `summarizer.py` — deterministic markdown render. Per-detector breakdown pinned above per-severity sections (mirrors F.3 / D.4 / multi-cloud-posture / k8s-posture). CRITICAL findings pinned. **Privacy-contract assert: `assert classifier_matched_text_never_in_report`** (Q6) — render layer scrubs any accidental leak.                                                                                                                                             |
| 12   | ⬜     |        | Agent driver `run()` — 7-stage pipeline. 2-feed TaskGroup ingest. Stage 4 CORRELATE reads `--cloud-posture-workspace` if present (Q4). Stage 5 SCORE applies severity uplift from correlation. `(contract, *, llm_provider, ...)` signature confirmed. 11th agent under ADR-007. Audit chain: 8 events (per-stage).                                                                                                                                                     |
| 13   | ⬜     |        | 10 representative YAML eval cases: `clean_account` / `public_bucket_no_pii` / `public_bucket_with_pii_critical` / `unencrypted_with_pii` / `sensitive_location_violation` / `oversharing_iam_no_pii` / `oversharing_iam_with_pii` / `correlation_uplift_from_f3` / `no_correlation_workspace_absent` / `no_pii_leak_in_report` (Q6 acceptance probe).                                                                                                                   |
| 14   | ⬜     |        | `DataSecurityEvalRunner` registered via `nexus_eval_runners`. **10/10 acceptance** green via `uv run eval-framework run --runner data_security --cases ... --output ...`. Tests + repo-wide gate.                                                                                                                                                                                                                                                                       |
| 15   | ⬜     |        | CLI (`data-security eval` / `data-security run`) — two subcommands; two required-or-defaulted feed flags (`--s3-inventory-feed` / `--s3-objects-feed`) + optional `--cloud-posture-workspace` (Q4) + optional `--customer-domain` allowlist (mirrors multi-cloud-posture's GCP IAM pattern; reserved for v0.2 use). One-line digest; warning on no-feed. README + smoke runbook (`runbooks/aws_dev_account_smoke.md`, 8 sections).                                      |
| 16   | ⬜     |        | Verification record (`docs/_meta/d-5-data-security-v0-1-verification-2026-05-20.md`). ADR-007 v1.1 + v1.2 conformance verified end-to-end; v1.3 + v1.4 opt-outs confirmed. Coverage ≥ 80% on `data_security.*`. WI-1 (substrate sealed) verified empty-diff. **D.5 v0.1 done; first of 7 unbuilt agents shipped under Path-B operating rule. Next: D.8 Threat Intel v0.1.**                                                                                             |

ADR references: [ADR-001](../../_meta/decisions/ADR-001-monorepo-bootstrap.md) · [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) · [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md) · [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) · [ADR-008](../../_meta/decisions/ADR-008-eval-framework.md) · [ADR-009](../../_meta/decisions/ADR-009-memory-architecture.md) · [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md).

---

## Resolved questions

| #   | Question                                              | Resolution                                                                                                                                                                             | Task            |
| --- | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| Q1  | Schema reuse strategy?                                | **Re-export F.3's `class_uid 2003` Compliance Finding** with `types[0]="data_security"` discriminator + `DataSecurityFindingType` enum (4) + `ClassifierLabel` enum (7+NONE). No fork. | Task 2          |
| Q2  | Live SDK calls or offline fixtures in v0.1?           | **Offline filesystem snapshots only** (mirrors F.3 / multi-cloud-posture). Live boto3 path ships D.5 v0.2.                                                                             | Tasks 4–5       |
| Q3  | Classifier — agent-local or charter substrate?        | **Agent-local** under `data_security/classifiers/`. Promotion to `charter.data_classification` deferred per ADR-007 3rd-consumer rule.                                                 | Task 3          |
| Q4  | F.3 cross-correlation — automatic or operator-pinned? | **Operator-pinned** via `--cloud-posture-workspace`. Mirrors D.7's sibling-workspace pattern. v0.1 NOT autodiscovery.                                                                  | Task 12         |
| Q5  | Tenancy in v0.1?                                      | **Single-tenant** (`semantic_store=None` opt-in default). Multi-tenant blocks on future SET LOCAL `$1` fix.                                                                            | Task 12         |
| Q6  | Privacy contract — never log values?                  | **Hard contract.** Classifier returns label only; render layer scrubs leaks. Eval case `no_pii_leak_in_report` is the acceptance probe.                                                | Tasks 3, 11, 13 |

---

## File map (target)

```
packages/agents/data-security/
├── pyproject.toml                              # Task 1
├── README.md                                   # Tasks 1, 15
├── runbooks/
│   └── aws_dev_account_smoke.md                # Task 15
├── src/data_security/
│   ├── __init__.py                             # Task 1
│   ├── py.typed                                # Task 1
│   ├── schemas.py                              # Task 2 (F.3 re-exports + DataSecurityFindingType + ClassifierLabel)
│   ├── nlah_loader.py                          # Task 10 (21-LOC shim)
│   ├── classifiers/
│   │   ├── __init__.py
│   │   └── patterns.py                         # Task 3 (regex + Luhn; classify(text) -> ClassifierLabel)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── s3_inventory.py                     # Task 4
│   │   └── s3_objects.py                       # Task 5
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── public_bucket.py                    # Task 6
│   │   ├── unencrypted.py                      # Task 7
│   │   ├── sensitive_location.py               # Task 8
│   │   └── oversharing.py                      # Task 9
│   ├── summarizer.py                           # Task 11
│   ├── agent.py                                # Task 12 (driver: 7-stage pipeline)
│   ├── eval_runner.py                          # Task 14
│   └── cli.py                                  # Task 15
├── nlah/
│   ├── README.md                               # Task 10
│   ├── tools.md                                # Task 10
│   └── examples/                               # Task 10 (2 examples)
├── eval/
│   └── cases/                                  # Task 13 (10 YAML cases)
└── tests/
    ├── test_pyproject.py                       # Task 1
    ├── test_schemas.py                         # Task 2
    ├── test_classifiers_patterns.py            # Task 3
    ├── test_tools_s3_inventory.py              # Task 4
    ├── test_tools_s3_objects.py                # Task 5
    ├── test_detectors_public_bucket.py         # Task 6
    ├── test_detectors_unencrypted.py           # Task 7
    ├── test_detectors_sensitive_location.py    # Task 8
    ├── test_detectors_oversharing.py           # Task 9
    ├── test_nlah_loader.py                     # Task 10
    ├── test_summarizer.py                      # Task 11
    ├── test_agent.py                           # Task 12
    ├── test_eval_runner.py                     # Task 14 (incl. 10/10 acceptance)
    └── test_cli.py                             # Task 15
```

---

## Risks

| Risk                                                                                                                                                                                                         | Mitigation                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Q6 privacy contract leak: a regex group accidentally captures the matched substring and the substring ends up in a finding's `evidence` field or in `report.md`.                                             | Eval case `no_pii_leak_in_report` is the load-bearing assertion. Classifier API typed to return `ClassifierLabel` only (no `MatchSpan`); summarizer renders labels not substrings. Any future change to the classifier signature requires Q6 re-verification.                                                            |
| Schema re-export from F.3 creates coupling; if F.3 amends `Severity` or `AffectedResource`, D.5 has to follow.                                                                                               | Acceptable — Compliance Finding schema is stable v0.1 and proven across two prior re-exporters (multi-cloud-posture, k8s-posture). v0.1 ships one re-export site; we monitor for breakage.                                                                                                                               |
| 4 detector rules + classifier + correlation = larger v0.1 surface than zero-substrate sketches imply.                                                                                                        | Each detector is a pure function with its own test file. ~10-12 tests per detector × 4 = ~50 detector tests, plus classifier (~30), tools (~20), schemas (~15), summarizer (~15), agent (~10), eval (~15) ≈ ~150 tests total. Comparable to F.3 v0.1 (~138 tests). Within the F.3 reference template's expected surface. |
| Operator-pinned `--cloud-posture-workspace` (Q4) is the only correlation hook; if F.3 findings format drifts, D.5 silently degrades to no-correlation.                                                       | Reader validates F.3 finding shape via pydantic; on validation failure, emits a one-line warning + continues without correlation (don't fail the run on a sibling agent's drift). Eval case `correlation_uplift_from_f3` is the acceptance probe; `no_correlation_workspace_absent` confirms standalone mode works.      |
| Classifier false-positive rate could be high on object-key samples (e.g., `email` regex matching log-formatted timestamps).                                                                                  | Q6 contract means false positives are non-disclosing (label only). The DETECT stage uses classifier hits as a severity-uplift signal, not as the only detection signal — public bucket alone is HIGH; classifier hit uplifts to CRITICAL. False positives at most over-classify severity, never leak data.               |
| 16K-byte content-sample limit per object means deeply-buried sensitive data could be missed.                                                                                                                 | Documented permanent limitation in README + runbook. Operators who need deeper scanning bring their own samples (Macie / Comprehend pre-process). D.5 v0.2's Macie cross-validation path expands the surface.                                                                                                            |
| F.4 control-plane tenant-context plumbing in v0.1 is single-tenant only (Q5); multi-tenant deployment will require ALL detector + classifier + correlation paths to be re-audited for SET LOCAL `$1` safety. | Acceptable for v0.1. Multi-tenant is owned by the future tenant-RLS substrate plan; D.5 v0.2's first task will be re-verifying multi-tenant primitives once that substrate ships. v0.1 carries the WI-3 watch-item: `semantic_store=None` default; SET LOCAL bug NOT touched.                                            |

---

## Watch-items (carry-forward to verification record)

- **WI-1: Substrate sealed.** No changes to `packages/charter/`, `packages/shared/`, `packages/eval-framework/`. Empty-diff proof at close per sketch §8 invariant 1.
- **WI-2: Classifier stays agent-local.** No charter hoist in v0.1 (revisit at 3rd consumer per ADR-007).
- **WI-3: Single-tenant.** `semantic_store=None` default; SET LOCAL `$1` bug NOT touched.
- **WI-4: Privacy contract Q6.** `no_pii_leak_in_report` eval case green; classifier API signature stable.
- **WI-5: No SAFETY-CRITICAL paths.** LOW-RISK label on every task PR.

---

## Done definition

D.5 Data Security v0.1 is **done** when:

- 16/16 tasks closed; every commit pinned in the execution-status table.
- ≥ 80% test coverage on `packages/agents/data-security` (gate same as F.3 / D.1 / D.3 / D.7 / D.4 / multi-cloud-posture / k8s-posture).
- `ruff check` + `ruff format --check` + `mypy --strict` clean.
- `eval-framework run --runner data_security` returns 10/10 (incl. Q6 privacy-contract acceptance probe).
- ADR-007 v1.1 + v1.2 conformance verified end-to-end; v1.3 + v1.4 opt-outs confirmed.
- README + smoke runbook reviewed.
- D.5 v0.1 verification record committed at `docs/_meta/d-5-data-security-v0-1-verification-2026-05-20.md` (or actual close date).
- Watch-items WI-1 through WI-5 verified at close.

That closes the **first of 7 unbuilt agents** under the Path-B operating rule. **D.8 Threat Intel v0.1** follows at the same cadence per sketch §8 sequence.

---

## ADR-011 cadence (per-task discipline)

Every numbered task above lands as its **own PR** off the branch `plan/d-5-data-security-agent`. Per [ADR-011](../../_meta/decisions/ADR-011-pr-flow-and-branch-protection-discipline.md):

- **LOW-RISK label** (title text) on every D.5 task — all changes are scoped to `packages/agents/data-security/` (new package, isolated). No SAFETY-CRITICAL paths (no `packages/charter/` or `packages/shared/` touches).
- **Report → review → merge → next task.** After each task commits + the PR is opened, pause for review. Don't start the next task until the prior task PR merges or is approved.
- **Verified-against-HEAD sentence** in PR body for every task: "Verified against HEAD = `<sha>` — tests + ruff + mypy green."
- **Execution-status table is single source of truth** for task-commit pinning per ADR-010. Verification record cites; does not duplicate.
- **No branching from a non-merged task PR.** Each task PR is opened from `plan/d-5-data-security-agent`; stacked PRs not used in v0.1.

---

## Next plans queued (for context, per Path-B operating rule)

- **D.5 Data Security v0.1** (this plan) — first of 7 unbuilt agents.
- **D.8 Threat Intel v0.1** — orthogonal; replicates D.4 Network Threat pattern.
- **D.6 Compliance v0.1** — cross-source framework-mapping over existing detect findings.
- **D.13 Synthesis v0.1** — LLM-driven cross-agent narration.
- **D.12 Curiosity v0.1** — depends on D.5 / D.6 / D.8 / D.13 having findings to reason over; needs F.7 `claims.>` subject ADR before plan starts.
- **A.4 Meta-Harness v0.1** — depends on all 6 D-track agents existing with eval suites; substrate-heavy.
- **Supervisor (#0) v0.1** — last; depends on all 17 prior agents; substrate-heaviest.

After Supervisor v0.1 closes (17/17 at v0.1), the Path-B operating rule opens the second-pass conversation: which agent's v0.2 first? That's a separate plan decision, driven by design-partner signal at that point.

---

## Reference template

Follows [ADR-007](../../_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md) (reference NLAH) + [ADR-010](../../_meta/decisions/ADR-010-version-extension-template.md) (within-agent version-extension template). No deltas from either; D.5 v0.1 is initial-version (not a within-agent extension), so ADR-010's "vN → vN+1" shape applies only to D.5 v0.2 and later (out of scope for this plan).
