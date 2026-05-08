# Contributing

## Workflow

1. Branch from `main`.
2. Implement against a sub-plan in `docs/superpowers/plans/`.
3. Commit using [Conventional Commits](https://www.conventionalcommits.org/).
4. Open a PR; fill the template; tag the relevant CODEOWNERS.
5. CI must pass (lint, typecheck, tests).
6. Two reviewers (CODEOWNER + one other).

## Local environment

- Node 20.11.1 (`nvm use`)
- Python 3.12 (`uv python install 3.12`)
- Go 1.22 or higher
- Docker Desktop (or compatible)

## Pre-commit

Husky runs lint-staged on every commit and commitlint on every commit message. If a commit is rejected, fix the issue and commit again — **do not** use `--no-verify`.

## Testing

- Python: `uv run pytest`
- TypeScript: `pnpm test`
- Go: `go test ./...`
- Everything: `pnpm test && uv run pytest && go test ./...`

## Conventions worth knowing

- TypeScript: `noUncheckedIndexedAccess` is enabled — every array/index lookup returns `T | undefined`. Handle the `undefined` case explicitly. This is intentional, not a bug.
- TypeScript packages targeting the browser must extend `tsconfig.base.json` and add `"DOM"` to `lib` in their package-level tsconfig.
- Python: monorepo-wide pytest uses `--import-mode=importlib`; do not add `tests/__init__.py` files.

## Charter compliance

Any code under `packages/agents/` must pass charter contract validation. New agents follow the Cloud Posture reference NLAH pattern (see `packages/agents/cloud-posture/nlah/README.md` once F.3 lands).
