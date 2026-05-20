# F.5 LTREE substrate fix — Task 7 diagnostic cleanup

**Plan-row-7 audit trail for the F.5 LTREE substrate-fix plan** ([`docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md)). Records the retirement of the throwaway diagnostic that captured the red signal which proved the LTREE bug existed, now that the permanent CI workflow + the LTREE substrate fix together have rendered the diagnostic redundant.

## What's being retired

| Artifact                                    | Where it lived                                                                  | Why it was created                                                                                                                                                          | Why it's retired now                                                                                                                                             |
| ------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/f5-ltree-diagnostic.yml` | Branch `diagnostic/f5-ltree-bug-repro`, commit `ecbb0e6` — never merged to main | One-off, throwaway CI workflow created to surface the F.5 LTREE substrate bug in CI for the first time                                                                      | The bug it surfaced is empirically fixed (Task 5 evidence-of-record); the permanent `.github/workflows/charter-f5-live.yml` (Task 4) is its standing replacement |
| Draft PR #42                                | `diagnostic/f5-ltree-bug-repro` → `main`; OPEN as of 2026-05-19                 | Wrapped the diagnostic workflow + carried the red CI evidence ([CI run `26082292289`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289)) | The red evidence remains immutable on GitHub Actions; closing the PR retires the open artifact without erasing the record                                        |
| Branch `diagnostic/f5-ltree-bug-repro`      | `origin` remote                                                                 | Held the single throwaway commit `ecbb0e6`                                                                                                                                  | Plan complete; the branch has no further role                                                                                                                    |

## The red signal it captured — preserved as immutable history

The diagnostic's purpose was to produce a reproducible red CI run that empirically confirmed the LTREE substrate bug existed (kg-loop-closure-verification-2026-05-18.md §13.2). That run is:

- **CI run [26082292289](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289)**: completed / failure (2026-05-19), 6 errors in 5.36s, every test errored at fixture setup with `AttributeError: module 'sqlalchemy.dialects.postgresql' has no attribute 'LTREE'` at `packages/charter/src/charter/memory/models.py:106`.

**This run is immutable on GitHub Actions.** Closing PR #42 and deleting the branch does NOT erase it. The run remains accessible via its URL for as long as the GitHub Actions log-retention policy holds. The verification record at [`f5-ltree-fix-task-5-live-proof-2026-05-19.md`](f5-ltree-fix-task-5-live-proof-2026-05-19.md) cites this run by URL as the empirical baseline against which the post-fix run [`26088948053`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053) is compared. Retiring the diagnostic does not retire the evidence.

## The permanent replacement

`.github/workflows/charter-f5-live.yml` (Task 4, commit `32897b8`) is the diagnostic's standing replacement. The two workflows shared:

- Same Postgres service image (`pgvector/pgvector:pg16`)
- Same Postgres provisioning (`POSTGRES_USER=nexus` / `POSTGRES_PASSWORD=nexus_dev` / `POSTGRES_DB=nexus`)
- Same healthcheck (`pg_isready -U nexus`)
- Same target test file (`packages/charter/tests/integration/test_memory_live_postgres.py`)
- Same `NEXUS_LIVE_POSTGRES=1` gating

The differences that make the permanent workflow the _replacement_, not just a copy:

| Difference | Diagnostic (`f5-ltree-diagnostic.yml`)                            | Permanent (`charter-f5-live.yml`)                                                                                                                                |
| ---------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trigger    | Only on changes to the diagnostic file itself                     | Any PR touching the charter substrate (`packages/charter/src/charter/memory/**`, `packages/charter/alembic/**`, the live test file, or the workflow file itself) |
| Lifecycle  | Throwaway — designed to be deleted after capturing one red signal | Permanent — runs on every relevant PR forever                                                                                                                    |
| Role       | Diagnostic-only (red signal surfacing)                            | Regression-detection (catches the next LTREE-class latent substrate bug at PR-review time, before it ships)                                                      |

The permanent workflow is doing this exact job already: Task 4's commit triggered the workflow against the patched substrate, producing the rescoped 1 PASS + 5 separately-tracked FAIL result documented in Task 5 — surfacing the SET LOCAL `$1` tenant-RLS bug for the first time. **The workflow proves its own value within hours of going live.**

## Cleanup actions (executed)

1. **PR #42 closed** with a comment naming Task 5's evidence-of-record + Task 4's permanent workflow as the replacement.
2. **Branch `diagnostic/f5-ltree-bug-repro` deleted** from `origin` after PR #42 closure.
3. **Workflow file `.github/workflows/f5-ltree-diagnostic.yml` retired** — the file never reached `origin/main`, so its deletion is automatic via the branch delete.

The cleanup leaves no lingering branches, no orphan PRs, no obsolete CI workflows. The historical red-signal CI run (`26082292289`) remains accessible at its URL.

## What this PR's diff contains

This PR is the **audit-trail commit** for the cleanup. It does NOT delete the workflow file (the file never existed on main; nothing to git-rm). It contains:

| File                                                              | Change                                        |
| ----------------------------------------------------------------- | --------------------------------------------- |
| `docs/_meta/f5-ltree-fix-task-7-diagnostic-cleanup-2026-05-20.md` | NEW — this audit-trail document               |
| `docs/superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md`     | Plan row 7 hash-pin: `⬜ pending` → `✅ done` |

The GitHub-side cleanup (PR close + branch delete) is executed alongside this PR's open and is not part of this PR's diff.

## Watch-items at this proof

| #    | Item                                                                                                                    | Verification                                                                           |
| ---- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| WI-1 | charter UNTOUCHED EXCEPT `models.py` lines 92-130 + `tests/test_portable_ltree.py`                                      | Doc-only PR. ✅                                                                        |
| WI-2 | NO AGENT MODIFIED (all 10 agents incl. cloud-posture)                                                                   | Doc-only PR. ✅                                                                        |
| WI-3 | Other carry-forwards remain separately sequenced                                                                        | No KG-loop test or agent code touched. ✅                                              |
| WI-4 | **Resolved here.** Diagnostic preserved through Tasks 1-6; retired now per the plan's explicit Task 7 cleanup directive | PR #42 closed; branch deleted; CI run `26082292289` preserved as immutable history. ✅ |

## Cross-references

- [Plan](../superpowers/plans/2026-05-19-f5-ltree-substrate-fix.md) — Task 7 row in the execution-status table.
- [Task 5 live proof](f5-ltree-fix-task-5-live-proof-2026-05-19.md) — the evidence-of-record for the LTREE fix; cites CI run `26082292289` as the pre-fix baseline.
- [Permanent workflow file](../../.github/workflows/charter-f5-live.yml) — the diagnostic's standing replacement (Task 4, commit `32897b8`).
- [Pre-fix CI run `26082292289`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26082292289) — the red signal the diagnostic captured. Remains immutable after this cleanup.
- [Post-fix CI run `26088948053`](https://github.com/gowthamprabakar/Nexus-Cyber-security-OS/actions/runs/26088948053) — the rescoped post-fix run on the permanent workflow.
- KG-loop closure verification record [§13.2](kg-loop-closure-verification-2026-05-18.md) — original source-of-record for the LTREE bug, now resolved.

---

**Task 7 complete. The throwaway diagnostic is retired. Only Task 8 (the plan-closer verification record) remains.**
