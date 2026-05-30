# Branch + PR + Commit Hygiene Audit — 2026-05-30

**Type:** Read-only fact-finding report. No branches deleted, no PRs closed, no commits rewritten.
**Repo:** `gowthamprabakar/Nexus-Cyber-security-OS`
**Default branch:** `main` (`765f25c` at audit time)
**Author:** audit performed against remote ground truth via `git` + GitHub API.
**Operator action:** review findings → draft a separate cleanup directive → execute cleanup one decision at a time in follow-up PR(s).

---

## 0. Headline findings (read this first)

1. **The session belief that G2 Tasks 2 and 4 were "merged" is wrong against remote ground truth.** PR #216 (Task 2 — `ExecutionContract.trigger_source`, SAFETY-CRITICAL) and PR #218 (Task 4 — `SkillMetadataEntry` effectiveness fields, SAFETY-CRITICAL) are both **OPEN** with a **failing `python-tests` check**. Neither charter change is on `main`. Verified: `git show origin/main:packages/charter/src/charter/contract.py | grep trigger_source` → empty; same for `nlah_loader.py` effectiveness fields.

2. **Cadence inversion in G2.** Task 3 (#217, supervisor `DelegationContract.trigger_source`) **merged ahead of** its plan-sibling Task 2 (#216, the charter field). Main is not broken — Task 3's supervisor code is self-consistent (`IncomingTask.trigger_source` is a supervisor-side enum) — but the ADR-011 task ordering was not preserved, and the charter substrate field the plan sequences first is still unmerged.

3. **Two completed cycles (F.5 LTREE, KG-loop) were never formally closed on the remote** — their **live-Postgres proof PRs are stranded open** (#48, #38), stalled because the live-Postgres CI can't go green (the known SET LOCAL `$1` tenant-RLS bug, 5/6 F.5 live tests failing). The substrate fixes and verification records DID merge; the empirical proof + permanent CI guard did not. The `charter-f5-live.yml` CI workflow (PR #47) is **confirmed not on main** — the live regression guard the F.5 cycle intended does not exist on `main`.

4. **Post-discipline commit traceability is 100%.** Every first-parent commit on `main` after the first PR appeared (2026-05-17 13:01) traces to a PR. Zero direct-pushes after ADR-011 adoption. The 355 untraced first-parent commits are **entirely** the pre-ADR-011 bootstrap era (single-author direct commits, all before 2026-05-17 12:13).

5. **130 stale branches accumulate because auto-delete-head-branches is OFF.** 119 are merged and safe to delete. Zero orphan branches (every branch maps to a PR).

6. **No PR has ever recorded a GitHub review.** The `main-protection` ruleset requires **0 approving reviews** — `reviewDecision` is `NULL` for all 218 PRs. ADR-011's "manual operator approval" is a human process, not enforced or recorded by GitHub. (So the §2b "approved-but-never-merged" category is empty by construction.)

---

## 1. Branch inventory

**Totals:** 131 remote branches (incl. `main`) → 130 non-main branches.

| Category         | Count | Meaning                                                                                  |
| ---------------- | ----: | ---------------------------------------------------------------------------------------- |
| MERGED-DELETABLE |   119 | Has a merged PR and/or is in `main`'s ancestry. Cleanup candidates (auto-delete is OFF). |
| ACTIVE-OPEN-PR   |    10 | Has a currently-open PR. Keep until PR resolves.                                         |
| CLOSED-NO-MERGE  |     1 | `feat/a-4-v0-2-task-15-cli` (PR #192, superseded).                                       |
| ORPHAN-NO-PR     |     0 | None — every branch maps to a PR. Strong discipline.                                     |

Single committer across all branches: `gowthamprabakar`. Date range: 2026-05-17 → 2026-05-26 (recent), with the bulk of merged-deletable branches 7–14 days old.

### 1.1 Active branches (open PRs) — sorted by staleness

| Branch                                             | PR   | Age | Ahead | Behind main | Notes                                            |
| -------------------------------------------------- | ---- | --: | ----: | ----------: | ------------------------------------------------ |
| `feat/g2-task-2-execution-contract-trigger-source` | #216 |  3d |     1 |           3 | SAFETY-CRITICAL; `python-tests` FAILING; BEHIND  |
| `feat/g2-task-4-nlah-loader-effectiveness-fields`  | #218 |  3d |     2 |           0 | SAFETY-CRITICAL; `python-tests` FAILING; BLOCKED |
| `docs/remaining-agents-sketch`                     | #52  |  9d |     1 |         248 | docs-only; CI green; deeply behind               |
| `feat/f5-ltree-task-5-live-proof`                  | #48  |  9d |    11 |         249 | SAFETY-CRITICAL; stacked; touches substrate      |
| `feat/f5-ltree-task-8-plan-closer-verification`    | #51  |  9d |    12 |         249 | stacked tip of F.5 chain                         |
| `feat/f5-ltree-task-1-grep-audit`                  | #44  | 10d |     5 |         249 | stacked base; touches substrate                  |
| `feat/f5-ltree-task-4-permanent-ci-workflow`       | #47  | 10d |     8 |         249 | `charter-f5-live-postgres` FAILING               |
| `docs/system-readiness-2026-05-19`                 | #41  | 10d |     1 |         250 | superseded by later readiness reports            |
| `feat/kg-loop-task-6-live-postgres-proof`          | #38  | 11d |     9 |         250 | SAFETY-CRITICAL; live-proof stranded             |
| `chore/branch-protection-require-ci`               | #6   | 12d |     1 |         344 | superseded by the live `main-protection` ruleset |

> The eight stale PRs (9–12d) are **249–344 commits behind main**. The `main-protection` ruleset has `strict_required_status_checks_policy: true` (require-up-to-date-before-merge), so each would need a rebase onto current `main` before it could merge regardless of content.

### 1.2 Merged-deletable branches (119) — cleanup candidates

These have merged PRs but persist because **`deleteBranchOnMerge` is false**. Full enumeration omitted for length; they cover the closed cycles in §5 (A.1, A.4 v0.1/v0.2, D.5, D.8, D.12, D.13, F.7 v0.1/v0.2, Supervisor v0.1, G1, plus merged tasks of F.5/KG-loop, and merged docs/chore branches). Representative examples: `feat/g1-task-1-bootstrap` … `feat/g1-task-16-verification-record`, `feat/d-5-task-*`, `feat/f-7-v0-*-task-*`, `feat/a-4-v0-2-task-*`, `plan/*` branches.

---

## 2. PR audit

**Totals (218 PRs):** 204 MERGED · 4 CLOSED-without-merge · 10 OPEN.

### 2a. Open PRs (10)

| PR   | Title (abbrev.)                                     | Label in title  | Age | CI             | Review | Merge state | Blocker                                            |
| ---- | --------------------------------------------------- | --------------- | --: | -------------- | ------ | ----------- | -------------------------------------------------- |
| #218 | G2 Task 4 — SkillMetadataEntry effectiveness fields | SAFETY-CRITICAL |  3d | 4ok/**1 fail** | none   | BLOCKED     | `python-tests` failing                             |
| #216 | G2 Task 2 — ExecutionContract.trigger_source        | SAFETY-CRITICAL |  3d | 4ok/**1 fail** | none   | BEHIND      | `python-tests` failing + behind main               |
| #52  | 7 remaining-agent sketches                          | LOW-RISK        |  9d | 5ok            | none   | UNKNOWN     | 248 behind; needs rebase                           |
| #51  | F.5 Task 8 — plan-closer verification record        | LOW-RISK        |  9d | 5ok            | none   | CLEAN       | 249 behind; stacked on #48/#47/#44                 |
| #48  | F.5 Task 5 — rescoped live proof                    | SAFETY-CRITICAL |  9d | 5ok            | none   | CLEAN       | 249 behind; live SET LOCAL bug parked              |
| #47  | F.5 Task 4 — permanent charter-f5-live CI workflow  | LOW-RISK        | 10d | 5ok/**1 fail** | none   | UNSTABLE    | `charter-f5-live-postgres` failing (SET LOCAL bug) |
| #44  | F.5 Task 1 — empirical grep audit                   | LOW-RISK        | 10d | 5ok            | none   | CLEAN       | 249 behind                                         |
| #41  | system readiness report 2026-05-19                  | LOW-RISK        | 10d | 5ok            | none   | UNKNOWN     | 250 behind; superseded                             |
| #38  | KG-loop Task 6 — live Postgres proof                | SAFETY-CRITICAL | 11d | 6ok            | none   | UNKNOWN     | 250 behind; live-proof stranded                    |
| #6   | require all 5 CI checks via ruleset                 | SAFETY-CRITICAL | 12d | 5ok            | none   | UNKNOWN     | 344 behind; superseded by live ruleset             |

**Labels:** none of the 10 open PRs carry a GitHub _label_ — the risk tag lives only in the PR _title_ text (`[SAFETY-CRITICAL]` / `[LOW-RISK]`). Label-based filtering/automation is therefore not possible today.

**Dependencies among open PRs:** #44 → #47 → #48 → #51 form a **stacked chain** (F.5 tasks 1→4→5→8); cumulative diff grows 194→456→734→1161 insertions. They must merge in order or be squashed together.

### 2b. Approved-but-never-merged (the core drift check)

**Result: 0 PRs.** Across all 218 PRs, `reviewDecision` is `NULL` for every one — no PR has ever received a GitHub _approving review_. This is a direct consequence of the ruleset requiring **0 approvals** (§4). There is therefore no population of "reviewed work nobody merged" in the GitHub-review sense. The _human_ review-and-merge step (ADR-011 operator approval) leaves no GitHub-recorded trail. **This is itself a finding:** the review process is invisible to GitHub tooling.

### 2c. Closed-without-merge PRs (4)

| PR   | Branch                           | Reason (assessed)                                                                                                                                                                     |
| ---- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| #1   | `phase-1a-foundations-complete`  | Pre-ADR-011 bootstrap; foundations landed via direct commits to main. Correctly closed.                                                                                               |
| #42  | `diagnostic/f5-ltree-bug-repro`  | Title says "expected red — DO NOT MERGE." Intentional diagnostic to reproduce the F.5 bug. Correctly closed.                                                                          |
| #192 | `feat/a-4-v0-2-task-15-cli`      | Superseded by #193 (`a-4-v0-2-task-15-cli-eval-stub`, MERGED). Branch still on remote (2 ahead).                                                                                      |
| #203 | `feat/g1-task-7-feedback-parser` | Re-landed: G1 task-7 work is on `main` as `skill_feedback.py` + `test_g1_feedback_parser.py` (commit `1bfb932`, confirmed ancestor of main). G1 is genuinely 16/16. Correctly closed. |

No "replaced by direct push" anti-pattern found among closed PRs.

---

## 3. Commit-history sanity check

### 3a. Main-branch traceability

- First-parent commits on `main`: **552**. Total commits (incl. squashed task commits): 708 over 6 months (all within May 2026 — repo is ~3 weeks old).
- Two merge strategies coexist: **true merge commits** (`Merge pull request #N …`, recent PRs #193+) and **squash merges** with `(#N)` suffix (mid-era). Both preserve PR linkage.
- Raw first-parent traceability: **197/552 (35%)** carry an explicit PR reference in the subject.

**This 35% is not a review-bypass rate.** Splitting by the ADR-011 transition:

| Era                   | Boundary                        | Traceability                              |
| --------------------- | ------------------------------- | ----------------------------------------- |
| Pre-ADR-011 bootstrap | up to 2026-05-17 **12:13:31**   | 355 direct commits, no PR (single author) |
| First PR merge        | 2026-05-17 **13:01:58** (PR #2) | —                                         |
| Post-ADR-011          | after first PR                  | **0 untraced commits — 100% via PR**      |

Verified: `git log origin/main --first-parent --reverse` → after the first PR-merge commit appears, there are **zero** subsequent untraced first-parent commits. Every line that lands on `main` post-discipline came through a PR.

### 3b. Force-push detection on main

The `main-protection` ruleset enforces **`non_fast_forward`** (force-push to main impossible) and **`deletion`** (main cannot be deleted), with **no bypass actors** (applies to admins). No evidence or possibility of force-push to `main` since the ruleset was created (2026-05-17 14:58). Pre-ruleset reflog is not available from the remote, but the pre-ADR-011 era was a linear single-author bootstrap.

### 3c. Co-authored commits

- **501 / 708** commits on `main` carry a `Co-Authored-By` trailer (AI-assisted attribution).
- Attribution targets: Claude Opus 4.7 (1M context) (majority), Claude Opus 4.7, Claude Sonnet 4.6.
- **Minor hygiene nit:** trailer casing is inconsistent — `Co-Authored-By:` (most) vs `Co-authored-by:` (80 commits). GitHub recognizes both; no action required, noted for completeness.
- Sole human author/committer: `gowthamprabakar`.

---

## 4. GitHub settings audit

### 4a / 4c. Branch protection — implemented as a **Ruleset**, not classic protection

Classic branch protection: **404 Branch not protected.** Protection is enforced via repository **ruleset `main-protection`** (id 16499639, `enforcement: active`, created 2026-05-17 14:58, **no bypass actors**, target `~DEFAULT_BRANCH`):

| Rule                                                             | Setting                                                          |
| ---------------------------------------------------------------- | ---------------------------------------------------------------- |
| `deletion`                                                       | main cannot be deleted                                           |
| `non_fast_forward`                                               | force-push to main blocked                                       |
| `pull_request` → required approving reviews                      | **0**                                                            |
| `pull_request` → dismiss stale / require last-push approval      | false / false                                                    |
| `required_status_checks`                                         | `python-tests`, `python`, `typescript-tests`, `typescript`, `go` |
| `strict_required_status_checks_policy` (up-to-date before merge) | **true**                                                         |

**Implications:**

- PRs **can merge with zero approvals** — there is no GitHub-enforced review gate. (Explains §2b.)
- `strict = true` means every PR must be **up-to-date with main before merge** — this is the hard blocker on the 8 stale PRs (249–344 behind). They cannot merge without a rebase even when green.
- 5 required checks; failing `python-tests` blocks #216/#218; failing `charter-f5-live-postgres` blocks #47.
- PR #6 ("require all 5 CI checks via ruleset") is **redundant/superseded** — the ruleset already enforces exactly these 5 checks and predates the PR's last activity.

### 4b. Auto-delete head branches

`deleteBranchOnMerge: false` — **OFF**. This is the direct cause of the 119 merged-but-undeleted branches in §1.2.

---

## 5. Cycle traceability

| Cycle                       | Merged |                    Open |     Closed-no-merge | Status                                                        |
| --------------------------- | -----: | ----------------------: | ------------------: | ------------------------------------------------------------- |
| A.1 v0.1.1 Remediation      |      8 |                       0 |                   0 | **CLOSED**                                                    |
| A.4 v0.1 Meta-Harness       |     17 |                       0 |                   0 | **CLOSED**                                                    |
| A.4 v0.2 Meta-Harness       |     17 |                       0 | 1 (#192 superseded) | **CLOSED**                                                    |
| Supervisor v0.1             |     17 |                       0 |                   0 | **CLOSED**                                                    |
| D.5 Data-security           |     17 |                       0 |                   0 | **CLOSED**                                                    |
| D.8 Threat-intel            |     17 |                       0 |                   0 | **CLOSED**                                                    |
| D.12 Curiosity              |     16 |                       0 |                   0 | **CLOSED**                                                    |
| D.13 Synthesis              |     16 |                       0 |                   0 | **CLOSED**                                                    |
| F.7 v0.1 Fabric             |      9 |                       0 |                   0 | **CLOSED**                                                    |
| F.7 v0.2 Events migration   |      9 |                       0 |                   0 | **CLOSED**                                                    |
| ADR-012 claims              |      1 |                       0 |                   0 | **CLOSED**                                                    |
| G1 Effectiveness Scoring    |     16 |                       0 |  1 (#203 re-landed) | **CLOSED** (16/16)                                            |
| **G2 Skill Selection**      |      2 |      **2 (#216, #218)** |                   0 | **IN-FLIGHT** (current cycle)                                 |
| **F.5 LTREE substrate-fix** |      5 | **4 (#44,#47,#48,#51)** |  1 (#42 diagnostic) | **STALLED**                                                   |
| **KG-loop closure**         |      8 |             **1 (#38)** |                   0 | **STALLED** (verification record #40 merged; live proof open) |
| Docs/Chore (standalone)     |      9 |      **3 (#6,#41,#52)** |                   0 | mixed (superseded / stale)                                    |

**F.5 LTREE detail (the most important stalled cycle):** even-numbered tasks merged — task 2 substrate fix (PR #45, the `_PortableLtree` TypeDecorator now on `main`), task 3 mocked tests (#46), task 6 regression guard (#49), task 7 diagnostic cleanup (#50). Odd-numbered tasks stranded open — task 1 grep-audit (#44), task 4 **permanent live CI workflow** (#47), task 5 **live proof** (#48), task 8 **verification record** (#51). **Net:** the fix is on `main`, but the cycle has no merged verification record and **no permanent live-Postgres CI guard** (`charter-f5-live.yml` is not on main). The stall root cause is the SET LOCAL `$1` tenant-RLS bug keeping `charter-f5-live-postgres` red (consistent with the project's known-debt note: 5/6 F.5 live tests fail).

**KG-loop detail:** tasks 1–5, 7, 8 merged (verification record #40 is on main); only task 6 live-Postgres proof (#38) is stranded open — same live-CI root cause.

---

## 6. Recommendations

> The operator (Praba) reviews and approves each item before any destructive action. All cleanup happens in separate follow-up PR(s).

### 6.1 Branches safe to delete (after operator confirmation)

- The **119 merged-deletable branches** (§1.2). One-shot cleanup; all have merged PRs. Recommend doing this _after_ enabling auto-delete (6.6) so it doesn't recur.

### 6.2 Branches needing a decision

- `feat/a-4-v0-2-task-15-cli` (#192 closed, 2 ahead) — confirm fully superseded by #193, then delete.
- The 8 stale open-PR branches — decision flows from the PR decisions in 6.4/6.5.

### 6.3 Open PRs to drive to merge ASAP (current, valuable work)

- **#218 (G2 Task 4, SAFETY-CRITICAL)** and **#216 (G2 Task 2, SAFETY-CRITICAL)** — fix the failing `python-tests`, rebase #216 onto main, then merge **in plan order (#216 before #218)** to repair the cadence inversion. These unblock the locally-staged G2 Task 5 work. **Highest priority** — they are the active cycle and both SAFETY-CRITICAL charter changes are currently absent from main.

### 6.4 Open PRs needing re-review / rebase (stale > 9 days, far behind)

- **F.5 chain #44 → #47 → #48 → #51** — decide as a unit. The substrate fix already merged (#45), so these carry the grep-audit, **permanent live CI workflow**, live proof, and verification record. Recommend: rebase the chain onto current main and merge the **verification record (#51)** + **grep audit (#44)** regardless of the live-CI bug, and gate **#47/#48** (live proof + live CI) on the SET LOCAL tenant-RLS fix — or explicitly re-scope them. Either way, **land or formally re-scope the F.5 verification record** so the cycle is closed in the record, and decide whether the live-Postgres CI guard should exist on main.
- **#38 (KG-loop live proof)** — same SET LOCAL dependency; decide alongside the F.5 live PRs (merge once live CI is fixable, or re-scope/close with a note pointing at the tenant-RLS substrate-fix plan).

### 6.5 Open PRs to consider closing (superseded / stale)

- **#6** (`chore/branch-protection-require-ci`) — superseded by the live `main-protection` ruleset that already enforces all 5 checks. Recommend close with a pointer to ruleset id 16499639.
- **#41** (`system readiness 2026-05-19`) — superseded by later readiness reports. Recommend close (or merge as a historical snapshot if the operator wants the record).
- **#52** (`remaining-agents-sketch`) — 248 behind; confirm whether the sketch was absorbed into the Phase-1 wave build plan; if so, close.

### 6.6 GitHub settings to change

- **Enable "Automatically delete head branches"** (`deleteBranchOnMerge: true`) — stops future branch accumulation. Single highest-leverage hygiene change.
- **Decide on review enforcement.** The ruleset requires **0 approving reviews**, so ADR-011's "manual operator approval" is unenforced and unrecorded. If the discipline is meant to be real, set `required_approving_review_count: 1` (note: single-maintainer repos can't self-approve, so this may require a bot/second account — operator's call). At minimum, document that review is an out-of-band human step with no GitHub trail.

### 6.7 Cycles needing closure

- **F.5 LTREE** and **KG-loop** — land or re-scope their stranded live-proof/verification PRs so the verification records exist on `main`. Until then, both cycles are "done in code, open in record."
- **G2** — in-flight; closes naturally once #216/#218 and the remaining Tasks 5–8 land.

---

## Appendix — method & limitations

- **Data sources:** `git branch -r`, `git log` (first-parent + merge analysis), `git merge-base --is-ancestor`, `git diff --stat origin/main...<branch>`, and GitHub API via `gh` (`pr list/view --json`, `repos/.../rulesets`, `commits/{sha}/pulls`). Snapshot taken 2026-05-30 against `origin/main @ 765f25c`.
- **"Days since"** computed against 2026-05-30.
- **Traceability caveat:** squash- and rebase-merges create new SHAs on `main`, so subject-line matching undercounts; the ADR-011-transition split (§3a) is the accurate read, cross-checked with `commits/{sha}/pulls` API sampling (pre-ADR-011 samples return no PR association, consistent with direct commits).
- **Substrate-content caveat:** "HEAD not in main" for stale PRs is a _SHA-ancestry_ statement. Content overlap (e.g. F.5 `_PortableLtree` landed via the squashed #45, not the open task branches' SHAs) was checked file-by-file where it mattered; operator should still content-diff before closing any F.5/KG-loop PR.
- **No destructive operations performed.** WI-1 substrate seal respected: this change adds only `docs/_meta/branch-pr-hygiene-audit-2026-05-30.md`; `git diff --stat origin/main -- packages/charter/ packages/shared/` is empty.
