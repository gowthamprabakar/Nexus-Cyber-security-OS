# Branch protection — `main`

## What this captures

`main` requires **all five CI checks to pass** before any merge can complete. That is, every PR (including admin PRs) must show green on:

| Check              | Workflow |
| ------------------ | -------- |
| `python-tests`     | `ci`     |
| `python`           | `lint`   |
| `typescript-tests` | `ci`     |
| `typescript`       | `lint`   |
| `go`               | `lint`   |

In addition:

- A pull request is required (no direct push to `main`).
- `non_fast_forward` is enforced (no force-pushes to `main`).
- `deletion` is blocked (`main` cannot be deleted).
- `bypass_actors: []` — **no one can bypass these rules**, including repo admins. This is intentional. The structural enforcement was the entire point of introducing this rule. If a future emergency truly requires an admin bypass, the rule should be amended via a follow-up PR with explicit reasoning; do not bypass silently.

The ruleset definition is checked in at [`branch-protection.json`](./branch-protection.json).

## Why

PR #3 was merged with red CI because GitHub's merge button does not enforce CI by default. That gap allowed broken main state to accumulate (e.g., the pre-existing `python-tests` / `python` lint failures that PR #5 fixed). The protection rule makes red CI a **structural blocker**, not a discouraged one.

## How to apply (admin)

This requires repo admin permissions. After this PR merges:

```bash
gh api \
    -X POST \
    /repos/gowthamprabakar/Nexus-Cyber-security-OS/rulesets \
    --input .github/branch-protection.json
```

The API returns the created ruleset's `id` on success. Verify in the GitHub UI under **Settings → Rules → Rulesets** — the entry named `main-require-five-ci-checks` should appear and show `Active`.

### Re-applying / updating

The rule has a unique `name`, so re-running the `POST` will return `422 Unprocessable Entity` (name conflict). To update the rule:

```bash
# 1. List existing rulesets, find the id for 'main-require-five-ci-checks'.
gh api /repos/gowthamprabakar/Nexus-Cyber-security-OS/rulesets

# 2. PUT the updated payload to that id.
gh api \
    -X PUT \
    /repos/gowthamprabakar/Nexus-Cyber-security-OS/rulesets/<id> \
    --input .github/branch-protection.json
```

Or delete the existing ruleset in the UI and re-`POST`.

## How to verify the rule is live

After applying, open any PR against `main` (e.g., a one-line README typo PR). The PR's merge button should show **"Required status checks have not yet completed"** until all five CI checks finish, and **"Merge"** must become **disabled** if any of the five checks fails. If the button stays clickable while red checks are present, the rule is not live — re-check `gh api /repos/.../rulesets` output.
