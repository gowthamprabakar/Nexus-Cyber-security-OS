# v0.3 / Phase D — A-2.4 verification record: secrets-in-runtime → DSPM (2026-06-15)

> Closes **A-2.4** (and with it the **A-2 cycle**). Records the cross-agent
> secrets-in-runtime flow built per **ADR-015** (D.1 SCANS, DSPM EMITS), the
> verification evidence, and the honest scope boundaries.

## 1. What shipped (3 self-merge PRs)

| PR   | Side                 | What                                                                            |
| ---- | -------------------- | ------------------------------------------------------------------------------- |
| #685 | D.1 (vulnerability)  | Capture Trivy `Results[].Secrets[]` + write **redacted** `runtime_secrets.json` |
| #686 | DSPM (data-security) | Read that artifact → emit **OCSF 2003** `SECRET_EXPOSED_IN_RUNTIME`             |
| this | cross-agent          | run()-level e2e + multi-tenant + redaction + this verification record           |

## 2. The cross-agent contract (the seam)

D.1 writes `runtime_secrets.json` to its workspace; DSPM reads it via the
`--vulnerability-workspace` flag (mirrors the existing `--cloud-posture-workspace`
sibling-read). Artifact shape (categorical metadata ONLY):

```json
{ "schema_version": "0.1", "agent": "vulnerability", "run_id": "...",
  "secrets": [ {"rule_id","category","severity","title","target","start_line","end_line"} ] }
```

DSPM maps each hit to OCSF 2003 with finding_id `CSPM-RUNTIME-SECRET-NNN-<target>`
and the discriminator in `evidence.source_finding_type` (the fleet pattern).

## 3. Premise correction (surfaced during PR1, pause trigger #41)

The A-2.4 recon said secrets were "dropped in the normalizer (no CVE-ID)."
**Verified against main: false in mechanism.** The Trivy wrapper's `_flatten` only
pulled `Results[].Vulnerabilities[]` and ignored `Results[].Secrets[]` entirely —
so secrets were dropped at the _wrapper_, never reaching the normalizer. Trivy runs
secret scanning by default, so the array was already in the JSON; the fix was to
**capture** it (not un-gate a normalizer drop). Same ADR-015 decision + forks; the
touch-point moved from `normalizer.py` to `trivy.py` + `agent.py`. No scanner-flag
change was needed (lower blast radius).

## 4. Privacy boundary (hard, verified both ends)

The matched plaintext (Trivy `Match`/`Code`) is **NEVER captured or written**:

- **D.1 side** (`secrets.py`): `RuntimeSecretHit` reads only categorical fields;
  tests assert the plaintext is absent from both the hit repr and the serialized artifact.
- **DSPM side** (`secrets_ingest.py`): consumes categorical metadata only; the
  run()-level e2e asserts no plaintext (`AKIA…`) in the emitted `findings.json`.

This honors ADR-015 + the DSPM privacy contract (no plaintext in evidence).

## 5. Verification evidence

- D.1 (#685): wrapper captures secrets; redaction asserted; **287 pass / 12 skip**.
- DSPM (#686): discriminator added (drift-guard 4→5); ingest/map/redaction; **469 pass / 1 skip**.
- Cross-agent (this PR): run() with `vulnerability_workspace` emits the OCSF 2003
  secret finding; no-workspace path byte-identical; plaintext absent e2e; account_uid
  is the consuming tenant (multi-tenant). **data-security 472 pass / 1 skip.**
- Substrate seal (`packages/shared` + `packages/charter`) **EMPTY** across all three PRs.
- All additive: OCSF 2003 discriminator appended; `runtime_secrets.json` only written
  when secrets present → offline eval byte-identical on both agents.

## 6. Honest scope boundaries (carried to v0.3 close)

- **Registry-route secrets out of scope:** PR1 captures secrets from direct
  image/fs/host scans; secrets found inside `_scan_registry` images are a follow-up.
- **Coverage attribution:** secrets-in-runtime counts toward **DSPM** weighted
  coverage, not D.1 (per ADR-015 + baseline reconciliation #670) — avoids double-count.
- **Cross-agent timing:** DSPM reads AFTER D.1 writes within a tenant scan window; a
  missing/empty artifact is routine (zero findings, no error) — no orchestration
  guarantee added here (the supervisor sequences agents; out of A-2.4 scope).
- **AppSec secrets-in-code (Q-AppSec-4):** a future Track B contributor to the SAME
  DSPM OCSF 2003 emission point (ADR-015 §Rationale 3) — not built here.

## 7. A-2 cycle status — CLOSED

| Sub-cycle                                     | Status            |
| --------------------------------------------- | ----------------- |
| A-2.1 filesystem SCA (Trivy fs + cargo/gem)   | ✅ #671           |
| A-2.2 host OS-package scan (Trivy rootfs/vm)  | ✅ #672           |
| A-2.3 reachability correlator (+5.9pp earner) | ✅ #676/#677/#678 |
| A-2.4 secrets-in-runtime → DSPM (cross-agent) | ✅ #685/#686/this |

**Track A: A-1 + A-2 done.** Next: parallel mode — A-4 (D.2 effective-perms),
A-3 (CSPM + k8s depth), and B-1 (D.14 AppSec, per-PR review).

## 8. References

- ADR-015 — `decisions/ADR-015-secrets-in-runtime-ownership-boundary.md`.
- Recon — `v0-3-a-2-4-recon-2026-06-14.md`. A-2.3 verification precedent — A-2.3 cycle (#678).
- Contract seam — `vulnerability/secrets.py` (producer) ↔ `data_security/secrets_ingest.py` (consumer).
