# v0.3 — main branch-protection status + a Python-CI gap (2026-06-14)

> **Status:** Config-state record (Workstream 1B). Verified the live `main-protection` ruleset
> via `gh api`. The directive's goal (require up-to-date branches) is **already enabled** — but
> verification surfaced a separate, higher-value gap: the **Python CI checks are not required**.

## 1. Verified state of the `main-protection` ruleset (id 16499639, active)

```
enforcement: active
rules:
  - deletion
  - non_fast_forward
  - pull_request
  - required_status_checks:
      strict_required_status_checks_policy: TRUE   ← "require up to date before merge" — ON
      required checks: [ typescript-tests, typescript, go ]
```

**Workstream 1B's stated goal is already met:** `strict_required_status_checks_policy: true`
means GitHub already requires a branch be up-to-date before the merge button. The rebase hazard
is GitHub-gated at merge for the required checks; the team's pre-PR `merge-base` routine remains
belt-and-suspenders (and has caught the _local_ stale-branch case several times). **No change is
needed for the up-to-date requirement.**

## 2. ⚠️ The real gap — Python CI checks are NOT in the required set

The required checks are `typescript-tests`, `typescript`, `go`. The repo's CI also runs **`python`
and `python-tests`** (seen on every PR's status rollup) — but they are **not required by the
ruleset**. Implication: a **Python-only PR could satisfy the ruleset and merge even if the Python
checks failed** (the strict/up-to-date policy is computed against the _required_ checks only).

Nearly all v0.3 work is Python. This is a genuine merge-gate hole — more impactful than the
up-to-date toggle the workstream targeted. (In practice every v0.3 Python PR did pass its Python
checks, so nothing bad merged — but the gate did not _enforce_ it.)

## 3. Recommended fix (operator-reviewed config change — NOT applied here)

Add `python` + `python-tests` to the ruleset's required checks (preserving the existing three and
`strict: true`). Because this changes the merge gate for **every** PR, it is an operator-reviewed
change and is **not** applied in this doc — surfaced for approval. Exact contexts come from the
live status rollup (`python`, `python-tests`). Apply via `gh api` PATCH on the ruleset's
`required_status_checks` rule, or via Settings → Rules → main-protection → Require status checks.

**Risk note:** a required-check `context` must match the CI run name exactly; a typo would require
a never-completing check and block all merges. Hence operator review + verification (push a PR with
a deliberately-failing Python check → confirm GitHub blocks it) before relying on it.

## 4. Pause-trigger update

Pause trigger #5 ("rebase hazard") is **already GitHub-enforced for the required checks** (strict
on). It downgrades to belt-and-suspenders for the team's local `merge-base` routine. Adding the
Python checks (§3) would extend GitHub enforcement to the checks that actually matter for this repo.

## 5. References

- Live ruleset read — `gh api repos/.../rulesets/16499639` (2026-06-14).
- v0.3 / Phase D directive — Workstream 1B (branch protection).
