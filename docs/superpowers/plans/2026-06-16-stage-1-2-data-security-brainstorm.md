# v0.4 Stage 1.2 (A-6) — D.4 Data-security depth + database inventory — brainstorm

**Status:** brainstorm for operator review (per-PR review). Template locked at #712 + §9/§10 added.
**Directive:** `v0-4-directive-2026-06-16.md` §3 Stage 1.2 + Option X. **Catalogue:** #711 "D.4 Data Security (DSPM)".
**Agent:** `packages/agents/data-security`. **Discipline:** depth-first; per-agent ownership; seal EMPTY; live gated; offline byte-identical.

> ⚠️ R-1 numbering: directive calls this "A-6 / D.4 Data Security"; package is `data-security` (self-ID D.5 #11). v1.1 catalogue amendment reconciles. Package unambiguous.

## 1. Current state (recon vs main `fec57f8`)

| Capability                            | State                                                                  | Evidence                                                                                                |
| ------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Sources                               | **S3 (chartered) + Azure Blob + GCS (client-injected, NOT chartered)** | `tools/s3_inventory*.py`, `azure_blob_inventory.py`, `gcs_inventory.py`; unified `tools/data_source.py` |
| Classifiers                           | PII(7) + PHI(3) + PCI(3); **label-only privacy contract**              | `classifiers/patterns.py`; `ClassifierLabel` enum                                                       |
| RDS / DynamoDB / BigQuery / Snowflake | **absent** (docstring-deferred)                                        | no code                                                                                                 |
| kg_writer.py                          | **absent**                                                             | —                                                                                                       |
| run() output                          | OCSF **2003**; `findings.json` + `report.md`; 5-stage pipeline         | `agent.py`                                                                                              |

**Net-new:** RDS + DynamoDB + BigQuery classification (Snowflake → v0.5 per directive D-8) · database inventory discovery · `kg_writer.py`.

## 2. Goal + scope boundary

- **Goal:** D.4 classifies the 3 new database sources + writes data-classification + database inventory into the SemanticStore.
- **Covers:** RDS/DynamoDB/BigQuery content classification + DB inventory nodes; kg_writer.
- **Does NOT cover:** Snowflake (v0.5); the DB resource's cloud config (D.3/F.3 owns the RDS/DynamoDB node — D.4 _contributes_ `CONTAINS`→classification per catalogue ownership rule); identities reaching the data (D.2).

## 3. Approach — per component (options + rec)

- **3a RDS/DynamoDB/BigQuery classification.** Reuse the existing `DataSource` unify + classifier pipeline; add 3 source connectors (sample-based, mirror the S3 1% sample basis). Rec: **charter all new connectors** (the existing Azure/GCS connectors are client-injected/un-chartered — fold those into the charter too while here, for consistency — _flag as a small scope addition, operator confirm_).
- **3b Database inventory + kg_writer.** New `kg_writer.py` (copy the 6-agent pattern: `(SemanticStore, customer_id)`, cross-tenant guard, no-op when None). Writes **Data classification nodes** (catalogue D.4) + `CONTAINS`/`CLASSIFIED_AS`/`EXPOSES_DATA` edges to D.3-owned storage nodes. DB _inventory_ (the table/instance nodes themselves) is owned by D.3/D.5 — D.4 contributes classification; confirm node-vs-edge split per catalogue.
- **3c Sample basis + privacy.** Preserve the label-only privacy contract (no plaintext in evidence) across the new DB sources; sample-based (configurable %).

## 4. Sub-PR breakdown (self-merge cascade)

1. PR1 `kg_writer.py` + data-classification node schema + SemanticStore wiring (no-op when None).
2. PR2 RDS classifier connector + DB inventory contribution.
3. PR3 DynamoDB connector.
4. PR4 BigQuery connector.
5. PR5 (optional) charter the existing Azure/GCS connectors (consistency) — operator-confirm.
6. PR6 cycle verification + coverage doc + kg_writer e2e (gated).

## 5. Substrate, invariants, gates

- Seal EMPTY (per-agent kg*writer via existing SemanticStore; classifier additive). Privacy invariant: label-only, no plaintext (existing test gate extended to new sources). Live behind `NEXUS_LIVE*\*`; offline byte-identical. Self-merge cascade; shared-kg-interface touch → per-PR. Layer 27 before signal.

## 6. Coverage + honest limitations

- Coverage `[estimate]`. Adds 3 DB sources + the data slice of the inventory graph. **Honest:** sample-based (not full-scan); Snowflake deferred (v0.5); classification depth bounded by the regex/ML classifier maturity; realized DB-classification lift lands on operator-run of live connectors.

## 7. Open decisions (operator)

1. Charter the existing Azure/GCS connectors while here (consistency) — yes/defer?
2. DB inventory node ownership — confirm D.3/D.5 own the DB node, D.4 contributes classification (per catalogue).
3. Sample % default for DB sources.

## 8. Template note

Same shape as #712. HOLD: no execution PRs until brainstorms approved.

## 9. Calendar estimate

~2-3 weeks (directive §12 Stage 1 budget; within Stage 1's deeper 8-12w envelope). 6 sub-PRs; mostly connector + classifier work on the existing pipeline.

## 10. Cross-references

- Catalogue (#711): "D.4 Data Security (DSPM)" — nodes owned (Data classification), edges (`CONTAINS`/`CLASSIFIED_AS`/`EXPOSES_DATA`), L2/L5.
- Directive §3 Stage 1.2 + D-8 (Snowflake→v0.5) + Option X (inventory folded).
- ADRs: no new ADR expected (per-agent, additive). Related: ADR-009 memory architecture (SemanticStore).
