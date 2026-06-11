# `nexus-data-security-agent`

Data Security Agent (DSPM) — **D.5**; **first of the 7 unbuilt agents** built under the [2026-05-20 Path-B-breadth-first operating rule](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md); **eleventh under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture / A.1 / **D.5**). Lifts platform coverage from CSPM-only into DSPM — the first agent that discovers + classifies sensitive data at rest.

> **v0.2 — operator Cycle 10 (`__version__` 0.1.0 → 0.2.0, 2026-06-11).** The DSPM cycle; data-security becomes the **5th OCSF 2003 emitter** (with F.3 / multi-cloud-posture / k8s-posture / compliance). Keeping the offline `run()`/eval byte-identical (WI-S5), this cycle adds: **live multi-cloud data discovery** — AWS S3 (`tools/s3_inventory_live.py` + `tools/s3_objects_live.py`, boto3 + charter Pattern A) + net-new **Azure Blob** + **GCS** (`tools/{azure_blob,gcs}_inventory.py`), **sample-based** (Q4 default 1%, mandatory `SampleBasis`, WI-S12) + a unified `DataSource` view; an **expanded classifier** — the v0.1 7-label PII set **+ HIPAA-aligned PHI** (MRN/ICD-10/NPI) **+ PCI** (CVV/expiration/track-data), all appended to the `classify()` precedence so prior matches stay byte-identical; **privacy-framework mapping** (`frameworks/` — GDPR/PCI-DSS/HIPAA); **data-residency tracking** (`residency/`, the moat); **D.2 Identity consumption** (`identity_consumption.py` + `access_risk.py` — sensitive-data + over-permissive-access uplift, advisory-only); and **continuous-monitoring INFRASTRUCTURE** (`continuous/` scheduler + delta + mode). Single gated lane `NEXUS_LIVE_DATA_SECURITY` (WI-S4 e2e). Setup: [`runbooks/`](runbooks/); per-source + per-data-type coverage (no aggregate, WI-S1/S2) + the closure record under `docs/_meta/data-security-v0-2-*`.
>
> **Privacy invariants (code-level — Nexus's moat).** `privacy.assert_privacy_contract` raises if a finding's evidence carries **plaintext** sensitive content — findings carry a classification **label + SHA-256 hash only** (WI-S8/S9); the **data-residency boundary** (WI-S10) means only metadata leaves the edge; every finding includes `sample_basis` (WI-S12). **Advisory only:** data-security emits + maps; it never enforces (A.1 Remediation owns enforcement).
>
> **Honest scope (WI-S3 / Path 1):** continuous mode is **INFRASTRUCTURE** at v0.2; wiring it into the agent's `run()` loop is the **Phase C consolidated retrofit** (after all 17 v0.2 cycles), NOT a v0.3 carry-forward. ML classification (Q3), full-bucket scanning (Q4), RDS/SQL/document-store sources (Q1), and ISO 27001 / SOC 2 / CCPA frameworks are v0.3+.

## What it does

Given an `ExecutionContract` requesting an AWS S3 data-security scan, D.5 runs a **seven-stage pipeline**:

```
INGEST → CLASSIFY → DETECT → CORRELATE → SCORE → SUMMARIZE → HANDOFF
```

Two concurrent input feeds (`asyncio.TaskGroup`):

- **S3 bucket inventory** — operator-staged JSON dump combining `aws s3api list-buckets` + per-bucket `get-bucket-acl` / `get-public-access-block` / `get-bucket-encryption` / `get-bucket-policy` / `get-bucket-tagging`.
- **S3 object samples** — operator-staged JSON of `{bucket, key, content_sample_b64}` triples, capped at 16 KiB per sample.

A **deterministic classifier** (regex + Luhn) labels each object sample as one of 7 PII categories (SSN / CREDIT_CARD / AWS_ACCESS_KEY / JWT / EMAIL / PHONE / GENERIC_API_TOKEN) or NONE. **Q6 privacy contract (load-bearing): the classifier returns LABEL ONLY — never the matched substring.**

Four pure-function detectors run per bucket, each producing OCSF v1.3 Compliance Findings (`class_uid 2003`) — **identical wire shape to F.3 / multi-cloud-posture / k8s-posture** with a `DataSecurityFindingType` discriminator:

- **`s3_bucket_public`** — ACL or BPA exposes the bucket. HIGH → CRITICAL with classifier hit.
- **`s3_bucket_unencrypted`** — no default SSE. MEDIUM → HIGH with classifier hit.
- **`s3_object_sensitive_in_untrusted_location`** — classifier hit AND bucket not tagged `Sensitivity=Restricted`. HIGH.
- **`s3_oversharing_iam`** — cross-account or wildcard read grants without MFA/IP/VPCE/OrgID condition guards. MEDIUM → HIGH with classifier hit.

Optional **F.3 cross-correlation** (Stage 4) reads a sibling cloud-posture workspace via `--cloud-posture-workspace`; when a finding matches an F.3 finding on the same bucket ARN, the **scorer** (Stage 5) uplifts severity one level (cap CRITICAL) and appends a `correlation_uplift` evidence entry.

A **deterministic summarizer** (Stage 6) renders the markdown report with CRITICAL pinned above per-severity sections + runs the classifier over the rendered output as the **Q6 render-layer assert** — if any matched PII pattern leaks into the report, `SummarizerQ6Violation` raises and the run fails.

## ADR-007 conformance

D.5 is the **11th** agent under the reference template. Inherits v1.1 (LLM adapter via `charter.llm_adapter`; no per-agent `llm.py`) and v1.2 (NLAH loader is a 21-LOC shim over `charter.nlah_loader` — D.5 is the **7th native v1.2 agent** after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture / k8s-posture). **Not** in the v1.3 always-on class — D.5 honours every budget axis. **Does not consume** the v1.4 candidate (sub-agent spawning primitive); single-driver per the agent spec.

**Schema reuse (Q1).** D.5 re-exports F.3's `class_uid 2003 Compliance Finding` schema verbatim — `Severity`, `AffectedResource`, `CloudPostureFinding`, `build_finding`, `FindingsReport`, `FINDING_ID_RE`. Adds `DataSecurityFindingType` enum (4 detectors) + `ClassifierLabel` enum (7 labels + NONE) on top. D.5 is the third re-exporter after multi-cloud-posture and k8s-posture.

LLM use: **not load-bearing**. Detectors + classifier + scorer + summarizer are all deterministic. The `LLMProvider` parameter on `agent.run` is plumbed but never called in v0.1 — keeps the contract surface stable when LLM-driven flows arrive in later versions.

## Q6 PRIVACY CONTRACT (load-bearing)

Per [PRD §7.1.4 lines 957-966](../../../docs/strategy/PRD.md), D.5 enforces a hard privacy contract: **the classifier returns a label only; matched substring is NEVER returned, NEVER logged, NEVER rendered.** Enforced at four layers:

1. **Return-type annotation.** `classify(text: str) -> ClassifierLabel` — mypy strict.
2. **No module state.** Classifier has no "last match" cache.
3. **No input logging.** Implementation does not log the input text.
4. **Render-layer assert.** Summarizer runs the classifier over the rendered markdown; if any pattern leaks, raises `SummarizerQ6Violation`.

System-level acceptance probe: eval case `010_no_pii_leak_in_report` — synthetic SSN + Visa test card in object samples MUST NOT appear in `findings.json` or `report.md`.

## Quick start

```bash
# 1. Run the local eval suite (10/10)
uv run data-security eval packages/agents/data-security/eval/cases

# 2. Run via the eval-framework (resolves through nexus_eval_runners entry-point)
uv run eval-framework run \
    --runner data_security \
    --cases packages/agents/data-security/eval/cases \
    --output /tmp/data-security-eval-out.json

# 3. Run against an ExecutionContract — two optional feeds + optional F.3 correlation
uv run data-security run \
    --contract path/to/contract.yaml \
    --s3-inventory-feed /tmp/s3-inventory.json \
    --s3-objects-feed /tmp/s3-objects.json \
    --cloud-posture-workspace /tmp/f3-workspace/ \
    --trusted-sensitivity-tag Restricted
```

See [`runbooks/aws_dev_account_smoke.md`](runbooks/aws_dev_account_smoke.md) for the full operator workflow (staging the two feeds + optional F.3 workspace · interpreting the three artifacts · severity escalation rules · routing findings to D.7 Investigation + A.1 Remediation + F.6 Audit · troubleshooting).

## Architecture

```
S3 bucket inventory ──→ read_s3_inventory ──┐
                                            ├──→ INGEST (TaskGroup)
S3 object samples   ──→ read_s3_objects ────┘
                                            │
                                            ▼
                              ┌─────────────────────────────────┐
                              │ CLASSIFY (regex + Luhn)         │   Q6: label only
                              │   classify(text) -> Label       │
                              └─────────┬───────────────────────┘
                                        ▼
                              ┌─────────────────────────────────┐
                              │ DETECT (4 pure-function rules)  │
                              │   public_bucket / unencrypted / │   per-detector
                              │   sensitive_location /          │   severity grading
                              │   oversharing_iam               │
                              └─────────┬───────────────────────┘
                                        ▼
                              ┌─────────────────────────────────┐
                              │ CORRELATE (optional)            │   Q4: operator-pinned
                              │   read_f3_findings +            │   --cloud-posture-workspace
                              │   correlate_with_f3             │
                              └─────────┬───────────────────────┘
                                        ▼
                              ┌─────────────────────────────────┐
                              │ SCORE (apply_correlation_uplift)│   one level up,
                              │   per-finding uplift            │   cap CRITICAL
                              └─────────┬───────────────────────┘
                                        ▼
                              ┌─────────────────────────────────┐
                              │ SUMMARIZE (deterministic md)    │   Q6 render-layer
                              │   render_summary + Q6 assert    │   assert runs here
                              └─────────┬───────────────────────┘
                                        ▼
                              ┌─────────────────────────────────┐
                              │ HANDOFF                         │
                              │   findings.json + report.md     │
                              │   + audit.jsonl (charter)       │
                              └─────────────────────────────────┘
```

Two async readers ([`tools/`](src/data_security/tools/)) + classifier ([`classifiers/`](src/data_security/classifiers/)) + four pure-function detectors ([`detectors/`](src/data_security/detectors/)) + correlation ([`correlate.py`](src/data_security/correlate.py)) + scorer ([`scorer.py`](src/data_security/scorer.py)) + summarizer ([`summarizer.py`](src/data_security/summarizer.py)) + driver ([`agent.py`](src/data_security/agent.py)).

## Output contract — the three artifacts

| File            | Format                                | Purpose                                                                                                                                          |
| --------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `findings.json` | `FindingsReport.model_dump_json()`    | Wire shape consumed by D.7 Investigation, A.1 Remediation, fabric routing. **OCSF 2003 — identical to F.3 / multi-cloud-posture / k8s-posture.** |
| `report.md`     | Markdown                              | Operator summary. CRITICAL pinned above per-severity sections. **Q6 render-layer assert verified before write.**                                 |
| `audit.jsonl`   | `charter.audit.AuditEntry` JSON-lines | This run's hash-chained audit log. F.6 `audit-agent query` reads it.                                                                             |

## Deferred to D.5 v0.2 / v0.3 / v0.4 / v0.5+

Per the [2026-05-20 version-roadmap §11](../../../docs/superpowers/sketches/2026-05-20-agent-version-roadmaps.md):

- **v0.2:** live boto3 SDK calls; classifier expansion (date-of-birth, addresses, healthcare IDs); AWS Macie cross-validation.
- **v0.3:** RDS + DynamoDB + RDS-snapshot scanning.
- **v0.4:** Azure Blob + Azure SQL + GCP Cloud Storage + BigQuery (multi-cloud DSPM).
- **v0.5+:** Snowflake + EFS + Kinesis; Bedrock / Vertex training-data forensics; Presidio custom classifier engine; toxic-combination detection cross-correlating D.6 / F.3.
- **Multi-tenant production** blocks on the future SET LOCAL `$1` tenant-RLS substrate-fix plan.

## Tests

```bash
uv run pytest packages/agents/data-security -q
```

**292 tests; 97% coverage on `data_security.*`; mypy strict clean.** **10/10 eval acceptance gate** via the eval-framework entry-point:

```bash
uv run eval-framework run --runner data_security \
    --cases packages/agents/data-security/eval/cases \
    --output /tmp/data-security-eval-out.json
# → 10/10 passed (100.0%)
```

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md). Substrate this agent consumes (`charter`, `cloud-posture`, `eval-framework`) is Apache 2.0; the agent itself is BSL.
