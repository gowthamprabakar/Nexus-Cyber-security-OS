# Cycle 5 — Credential Access breadth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Add two Credential-Access attack paths — IMDS/SSRF→cred-theft and broadened (cross-cloud)
stored-secret extraction — offline-proven through `scan_run`, growing the named catalog.

**Architecture:** Same injectable-seam + `fleet_testkit` pattern as the 4-cycle arc. New/extended
readers write nodes+properties; detectors in `meta_harness.kg_query` traverse existing edges
(`ASSUMES`, `HAS_ACCESS_TO`, `EXPOSES_DATA`, `STORES_SECRET`); ScanSources feeders drive them.

**Tech Stack:** Python, moto (AWS fixtures), uv workspace.

## Global Constraints

- **Security (verbatim, non-negotiable):** ONLY AWS AKIA/ASIA access-key IDs may be stored in clear.
  EVERY other credential (GCP SA key, Azure connection string, GitHub PAT, Slack token, DB password)
  MUST be fingerprinted via `secret_fingerprint(...)` — never the raw value on any node/edge/property.
- Live cloud stays `NEXUS_LIVE_*`-gated; offline path uses injected inputs / moto.
- Commit subjects lowercase, ≤100 chars; body lines ≤100. Husky clean, NEVER `--no-verify`.
- Before declaring a task done, run the covering tests AND `uv run mypy` (whole-repo, no path args) —
  path-args mis-resolve modules. Run `packages/charter` guard (ADR-016) if any agent `run()` changed.
- New named `path_type` registration checklist (a detector ripples into ~8 files):
  `_SEVERITY`+`_title` (attack_paths.py); `_OUT_OF_MODEL` (test_path_taxonomy);
  `REMEDIATION`+`_FIX` (attack_path_remediation.py);
  `_INTERNET_FACING`+`_generic_path_type`+`_generic_title` (report_card.py);
  `_LABELS` (attack_path_report.py).
- OCSF/graph evidence = ids / CVE / data-types only (no plaintext).

---

### Task 1: IMDS/SSRF → credential-theft archetype (`imds_credential_theft`)

**Files:**

- Modify: `packages/agents/cloud-posture/src/cloud_posture/tools/aws_ec2.py` (capture MetadataOptions)
- Modify: `packages/agents/cloud-posture/src/cloud_posture/tools/kg_writer.py` (write `imdsv1_enabled` prop)
- Modify: `packages/agents/meta-harness/src/meta_harness/kg_query.py` (new detector)
- Modify: `attack_paths.py`, `attack_path_remediation.py`, `report_card.py`, `attack_path_report.py`,
  `tests/test_path_taxonomy.py` (registration checklist)
- Modify: `packages/runtime/src/nexus_runtime/scan_pipeline.py` (ScanSources already carries
  `cloud_ec2_workloads`; no new seam — the property rides the existing feed)
- Test: `packages/agents/cloud-posture/tests/`, `packages/agents/meta-harness/tests/`,
  `packages/runtime/tests/integration/test_scan_pipeline_e2e.py`

**Interfaces:**

- Consumes: `Ec2Workload` (adds `imdsv1_enabled: bool = False`), `read_ec2_workloads` (reads
  `instance["MetadataOptions"]["HttpTokens"] == "optional"` → IMDSv1 enabled).
- Produces: `find_imds_credential_theft()` → hits keyed on `(instance_id, role_arn, sink)`; path_type
  `imds_credential_theft`.

**Graph pattern (green-for-right-reason):**
`CLOUD_RESOURCE{kind=ec2-instance, is_public=True, imdsv1_enabled=True}` --ASSUMES--> `IDENTITY`(role)
--HAS_ACCESS_TO--> `CLOUD_RESOURCE` --EXPOSES_DATA--> `DATA_CLASSIFICATION`. The discriminator is
`imdsv1_enabled` — a public instance whose role reaches data is only _metadata-cred-stealable_ when
IMDSv1 is on (fix = enforce IMDSv2). Negative case: `imdsv1_enabled=False` (IMDSv2 enforced) stays dark.

- [ ] **Step 1: Failing test — `Ec2Workload` carries IMDSv1 flag.** In cloud-posture tests, drive
      `read_ec2_workloads` against a moto instance launched with `MetadataOptions={'HttpTokens':'optional'}`;
      assert the returned workload has `imdsv1_enabled is True`; a second instance with `'required'` →
      `False`.
- [ ] **Step 2: Run it, verify it fails** (`imdsv1_enabled` doesn't exist yet).
- [ ] **Step 3: Implement** — add `imdsv1_enabled: bool = False` to `Ec2Workload`; in
      `read_ec2_workloads` set it from `inst.get("MetadataOptions", {}).get("HttpTokens") == "optional"`.
      In `kg_writer` record it as a property on the ec2-instance node (merge-safe).
- [ ] **Step 4: Run tests, pass.**
- [ ] **Step 5: Failing test — detector.** In meta-harness tests, seed the graph (public ec2-instance
      with `imdsv1_enabled=True` --ASSUMES--> role --HAS_ACCESS_TO--> resource --EXPOSES_DATA--> data);
      assert `find_imds_credential_theft` returns one hit; assert `imdsv1_enabled=False` → no hit; assert
      private instance → no hit.
- [ ] **Step 6: Run it, fails.**
- [ ] **Step 7: Implement the detector** in `kg_query.py` (mirror an existing exposed-instance
      detector's traversal; require `is_public` AND `imdsv1_enabled` on the source node) + a
      `ImdsCredentialTheft` result dataclass.
- [ ] **Step 8: Registration** — add `imds_credential_theft` to `_SEVERITY` (propose sev 82: exposed
  - role-to-data + a concrete exploitable cred-theft vector) + `_title`; the 5 other checklist files;
    normalize the hit in `attack_paths.py`.
- [ ] **Step 9: Run meta-harness suite + `test_path_taxonomy`, pass.**
- [ ] **Step 10: e2e** in `test_scan_pipeline_e2e.py` — inject a public EC2 (`cloud_ec2_workloads`)
      with IMDSv1 + a role fine-grained-granted to a PII bucket via `scan_run`; assert a confirmed
      `imds_credential_theft` path; assert IMDSv2 variant produces none.
- [ ] **Step 11: Whole-repo `uv run mypy` + `packages/charter` guard + `ruff` clean. Commit.**

### Task 2: Broadened / cross-cloud stored-secret extraction

**Files:**

- Modify: `packages/agents/cloud-posture/src/cloud_posture/tools/stored_secrets.py` (extend patterns +
  fingerprint non-AKIA)
- Test: `packages/agents/cloud-posture/tests/` (+ the existing `find_stored_secret_to_data` lights up)

**Interfaces:**

- Consumes: `stored_secret_grants(...)` — today AKIA-only, stores the raw AKIA id.
- Produces: same tuple shape, but now also matches GCP SA private-key blocks, Azure connection-string
  `AccountKey=`, GitHub PAT (`ghp_`/`github_pat_`), Slack (`xox[baprs]-`), generic
  `-----BEGIN PRIVATE KEY-----`. **Non-AKIA matches carry `secret_fingerprint(raw)`, NOT the raw value.**

**Graph pattern:** unchanged — the existing `find_stored_secret_to_data` detector (workload
--STORES_SECRET--> SECRET, SECRET reaches data) lights up for the new secret types automatically; the
SECRET node keys on the AKIA id (clear) or the fingerprint (everything else).

- [ ] **Step 1: Failing test** — `stored_secret_grants` over an env map containing a GCP SA key
      block, an Azure `AccountKey=`, and a `ghp_` PAT returns three secret grants; assert each non-AKIA
      secret's stored key == `secret_fingerprint(raw)` and `raw not in <stored key>`; an AKIA id stays clear.
- [ ] **Step 2: Run it, fails.**
- [ ] **Step 3: Implement** — add the patterns; route AKIA→clear, everything else→`secret_fingerprint`.
      Keep the tuple/return contract identical so no downstream change is needed.
- [ ] **Step 4: Run tests, pass** (+ confirm the existing `find_stored_secret_to_data` unit still green).
- [ ] **Step 5: Whole-repo `uv run mypy` + `ruff` clean. Commit.**

---

## Self-Review notes

- Task 1 is a new archetype → the registration checklist is load-bearing (test_path_taxonomy will fail
  if `_OUT_OF_MODEL`/`_SEVERITY` disagree). Task 2 adds NO path_type (rides the existing detector).
- The security constraint is the sharpest edge in Task 2 — the fingerprint test is the guard.
- Snapshot-secret + snapshot/AMI→data deliberately deferred to Cycle 6 (both need one new snapshot
  reader; build it once there).
