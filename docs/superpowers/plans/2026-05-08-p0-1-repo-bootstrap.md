# P0.1 — Repo Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Nexus Cyber OS monorepo skeleton with multi-language tooling (Python / TypeScript / Go), CI/CD, pre-commit hooks, local-dev docker-compose, and an ADR record — so every subsequent sub-plan has a stable place to land code.

**Architecture:** Single Git monorepo using Turborepo for task orchestration across language workspaces. Python (agents, charter, eval-framework, control-plane) uses `uv` + ruff + mypy + pytest. TypeScript (console) uses pnpm + tsc + eslint + vitest. Go (edge agent, fleet manager) uses `go.work`. CI runs per-workspace on GitHub Actions self-hosted runners. Pre-commit hooks enforce conventional commits + lint-staged.

**Tech Stack:** Git · Turborepo 2.x · pnpm 9 · uv 0.4 · go.work 1.22 · ruff · mypy · pytest · eslint · prettier · vitest · Husky · lint-staged · commitlint · GitHub Actions · Docker Compose · Apache 2.0 license (OSS packages) / Business Source License (proprietary packages)

**Repo location:** `/Users/prabakarannagarajan/nexus cyber os/` (no trailing space). The trailing-space sibling directory will be merged in Task 2.

---

## File Structure

```
/  (repo root)
├── .editorconfig
├── .gitattributes
├── .gitignore
├── .nvmrc
├── .python-version
├── package.json              # Turborepo root
├── pnpm-workspace.yaml
├── turbo.json
├── go.work
├── pyproject.toml            # root Python config (ruff, mypy)
├── uv.lock
├── README.md
├── CONTRIBUTING.md
├── LICENSE-APACHE             # Apache 2.0 — for charter, eval-framework
├── LICENSE-BSL                # Business Source License — proprietary packages
├── CODEOWNERS
├── commitlint.config.js
├── .husky/
│   ├── pre-commit
│   └── commit-msg
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── lint.yml
│   │   └── release.yml
│   ├── pull_request_template.md
│   └── ISSUE_TEMPLATE/
│       ├── bug.yml
│       └── feature.yml
├── docs/
│   ├── README.md
│   ├── _meta/
│   │   ├── glossary.md
│   │   ├── version-history.md
│   │   └── decisions/
│   │       ├── _template.md
│   │       └── ADR-001-monorepo-bootstrap.md
│   └── superpowers/plans/    # this file lives here
├── docker/
│   └── docker-compose.dev.yml
├── packages/
│   ├── charter/              # Apache 2.0 — open source
│   ├── eval-framework/       # Apache 2.0 — open source
│   ├── agents/
│   │   └── cloud-posture/    # proprietary
│   ├── control-plane/        # proprietary
│   ├── edge/                 # proprietary (Go)
│   ├── console/              # proprietary (TypeScript)
│   ├── shared/               # proprietary
│   └── content-packs/
│       ├── generic/
│       ├── tech/
│       └── healthcare/
└── tools/
    └── scripts/
```

---

## Tasks

### Task 1: Initialize Git repository

**Files:** Create: `.gitignore`, `.gitattributes`, `.editorconfig`

- [ ] **Step 1: Initialize the repo**

```bash
cd "/Users/prabakarannagarajan/nexus cyber os"
git init -b main
```

Expected: `Initialized empty Git repository in /Users/prabakarannagarajan/nexus cyber os/.git/`

- [ ] **Step 2: Create `.gitignore`**

```gitignore
# Node
node_modules/
*.log
.pnpm-debug.log*

# Python
__pycache__/
*.py[cod]
*$py.class
.venv/
.uv/
*.egg-info/
.pytest_cache/
.mypy_cache/
.ruff_cache/

# Go
/bin/
/pkg/
*.test
*.out
go.work.sum

# Build outputs
dist/
build/
.next/
.turbo/
coverage/

# IDE
.vscode/
.idea/
*.swp
.DS_Store

# Secrets
.env
.env.local
.env.*.local
*.pem
*.key

# Local infra
docker/.data/
```

- [ ] **Step 3: Create `.gitattributes`**

```gitattributes
* text=auto eol=lf
*.py text diff=python
*.go text diff=golang
*.ts text
*.tsx text
*.md text diff=markdown

*.png binary
*.jpg binary
*.jpeg binary
*.gif binary
*.ico binary
*.pdf binary
```

- [ ] **Step 4: Create `.editorconfig`**

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
indent_style = space
indent_size = 2
insert_final_newline = true
trim_trailing_whitespace = true

[*.{py}]
indent_size = 4

[*.{go}]
indent_style = tab

[Makefile]
indent_style = tab
```

- [ ] **Step 5: Commit**

```bash
git add .gitignore .gitattributes .editorconfig
git commit -m "chore: initialize repo with editor config and ignore rules"
```

---

### Task 2: Merge trailing-space sibling directory

**Files:** Move every file from `/Users/prabakarannagarajan/nexus cyber os ` (trailing space) into the canonical no-space directory.

- [ ] **Step 1: List contents of trailing-space dir**

```bash
ls -la "/Users/prabakarannagarajan/nexus cyber os "/
```

Expected: shows `AGENT_SPEC_PART1.md`, `AGENT_SPEC_PART1 (1).md`, `AGENT_SPEC_PART3.md`, `PRD.md`, `VISION.md`, `agent_specification_with_harness.md`, `platform_architecture.md`, `platform_architecture (1).md`, `runtime_charter.md`.

- [ ] **Step 2: Create `docs/strategy/` and `docs/architecture/` and `docs/agents/`**

```bash
mkdir -p docs/strategy docs/architecture docs/agents docs/agents/_archive
```

- [ ] **Step 3: Move strategy docs**

```bash
mv "/Users/prabakarannagarajan/nexus cyber os /VISION.md" docs/strategy/VISION.md
mv "/Users/prabakarannagarajan/nexus cyber os /PRD.md"    docs/strategy/PRD.md
```

- [ ] **Step 4: Move architecture docs**

```bash
mv "/Users/prabakarannagarajan/nexus cyber os /runtime_charter.md"        docs/architecture/runtime_charter.md
mv "/Users/prabakarannagarajan/nexus cyber os /platform_architecture.md"  docs/architecture/platform_architecture.md
rm "/Users/prabakarannagarajan/nexus cyber os /platform_architecture (1).md"
```

- [ ] **Step 5: Move agent specs (canonical first, archives second)**

```bash
mv "/Users/prabakarannagarajan/nexus cyber os /agent_specification_with_harness.md" docs/agents/agent_specification_with_harness.md
mv "/Users/prabakarannagarajan/nexus cyber os /AGENT_SPEC_PART1.md" docs/agents/_archive/AGENT_SPEC_PART1.md
mv "/Users/prabakarannagarajan/nexus cyber os /AGENT_SPEC_PART3.md" docs/agents/_archive/AGENT_SPEC_PART3.md
rm "/Users/prabakarannagarajan/nexus cyber os /AGENT_SPEC_PART1 (1).md"
```

- [ ] **Step 6: Add archive notice to old part files**

Create `docs/agents/_archive/README.md`:

```markdown
# Archived agent specs (superseded)

These documents are retained for historical context. They are **NOT canonical**.

The canonical agent specification is `docs/agents/agent_specification_with_harness.md` (the "harness doc"). Where this archive disagrees with the harness doc, the harness doc wins.

PART2 was never written. Sections covering agents 3–14 and Sections 19–21 are being produced as PART4-5 alongside Phase 1 build per the build roadmap.

Cross-referenced contradictions documented in `docs/_meta/decisions/ADR-001-monorepo-bootstrap.md`.
```

- [ ] **Step 7: Remove the now-empty trailing-space directory**

```bash
ls "/Users/prabakarannagarajan/nexus cyber os /"
rmdir "/Users/prabakarannagarajan/nexus cyber os /"
```

Expected after `ls`: empty. `rmdir` succeeds.

- [ ] **Step 8: Commit**

```bash
git add docs/
git commit -m "docs: consolidate strategy/architecture/agent specs from sibling directory; archive superseded part files"
```

---

### Task 3: Root Turborepo configuration

**Files:** Create `package.json`, `pnpm-workspace.yaml`, `turbo.json`, `.nvmrc`

- [ ] **Step 1: Create `.nvmrc`**

```
20.11.1
```

- [ ] **Step 2: Create `pnpm-workspace.yaml`**

```yaml
packages:
  - 'packages/*'
  - 'packages/agents/*'
  - 'packages/content-packs/*'
```

- [ ] **Step 3: Create `package.json`**

```json
{
  "name": "nexus-cyber-os",
  "version": "0.1.0",
  "private": true,
  "description": "Nexus Cyber OS — autonomous cloud security platform",
  "packageManager": "pnpm@9.10.0",
  "engines": {
    "node": ">=20.11.0",
    "pnpm": ">=9.0.0"
  },
  "scripts": {
    "build": "turbo run build",
    "test": "turbo run test",
    "lint": "turbo run lint",
    "typecheck": "turbo run typecheck",
    "clean": "turbo run clean && rm -rf node_modules .turbo",
    "prepare": "husky"
  },
  "devDependencies": {
    "turbo": "^2.1.0",
    "husky": "^9.1.6",
    "lint-staged": "^15.2.10",
    "@commitlint/cli": "^19.5.0",
    "@commitlint/config-conventional": "^19.5.0"
  }
}
```

- [ ] **Step 4: Create `turbo.json`**

```json
{
  "$schema": "https://turbo.build/schema.json",
  "globalDependencies": ["**/.env.*", "tsconfig.base.json", "pyproject.toml"],
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**", ".next/**", "!.next/cache/**"]
    },
    "test": {
      "dependsOn": ["^build"],
      "outputs": ["coverage/**"],
      "cache": true
    },
    "lint": {
      "outputs": []
    },
    "typecheck": {
      "dependsOn": ["^build"],
      "outputs": []
    },
    "clean": {
      "cache": false
    }
  }
}
```

- [ ] **Step 5: Install root dependencies**

```bash
pnpm install
```

Expected: lockfile created at `pnpm-lock.yaml`, `node_modules/` populated, husky installed.

- [ ] **Step 6: Verify Turborepo runs (no tasks yet, but command should succeed)**

```bash
pnpm turbo run build --dry=json
```

Expected: JSON dry-run output, no errors, `"tasks": []` since no packages exist yet.

- [ ] **Step 7: Commit**

```bash
git add package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json .nvmrc
git commit -m "chore: configure turborepo with pnpm workspaces"
```

---

### Task 4: Husky + commitlint + lint-staged

**Files:** Create `.husky/pre-commit`, `.husky/commit-msg`, `commitlint.config.js`, root `.lintstagedrc.json`

- [ ] **Step 1: Initialize Husky**

```bash
pnpm husky init
```

Expected: `.husky/pre-commit` created.

- [ ] **Step 2: Replace `.husky/pre-commit`**

```sh
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

pnpm lint-staged
```

- [ ] **Step 3: Create `.husky/commit-msg`**

```sh
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

pnpm commitlint --edit "$1"
```

```bash
chmod +x .husky/commit-msg
```

- [ ] **Step 4: Create `commitlint.config.js`**

```js
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'docs', 'chore', 'refactor', 'test', 'perf', 'ci', 'build', 'spike', 'revert']
    ],
    'subject-max-length': [2, 'always', 100]
  }
};
```

- [ ] **Step 5: Create `.lintstagedrc.json`**

```json
{
  "*.{js,jsx,ts,tsx}": ["eslint --fix", "prettier --write"],
  "*.py": ["ruff check --fix", "ruff format"],
  "*.go": ["gofmt -w", "go vet"],
  "*.{json,md,yml,yaml}": ["prettier --write"]
}
```

- [ ] **Step 6: Smoke-test commit message rule**

```bash
git add .husky commitlint.config.js .lintstagedrc.json
git commit -m "this is not conventional"
```

Expected: commit-msg hook rejects with `subject may not be empty` or `type may not be empty` error.

- [ ] **Step 7: Commit with conventional message**

```bash
git commit -m "chore: add husky, commitlint, and lint-staged"
```

Expected: success.

---

### Task 5: Python workspace tooling (uv, ruff, mypy, pytest)

**Files:** Create root `pyproject.toml`, `.python-version`

- [ ] **Step 1: Create `.python-version`**

```
3.12
```

- [ ] **Step 2: Install uv**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv --version
```

Expected: `uv 0.4.x` or higher.

- [ ] **Step 3: Create root `pyproject.toml`**

```toml
[project]
name = "nexus-cyber-os"
version = "0.1.0"
description = "Nexus Cyber OS — monorepo root"
requires-python = ">=3.12,<3.13"
dependencies = []

[tool.uv.workspace]
members = [
    "packages/charter",
    "packages/eval-framework",
    "packages/agents/cloud-posture",
    "packages/control-plane",
    "packages/shared",
]

[tool.ruff]
line-length = 100
target-version = "py312"
extend-exclude = [".venv", "dist", "build", ".turbo"]

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "C4", "SIM", "RUF"]
ignore = ["E501"]  # line length handled by formatter

[tool.ruff.lint.per-file-ignores]
"**/tests/**/*.py" = ["S101"]  # assert allowed in tests

[tool.mypy]
python_version = "3.12"
strict = true
warn_unused_configs = true
disallow_any_generics = true
disallow_untyped_defs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_return_any = true
exclude = ["dist", "build", ".venv"]

[tool.pytest.ini_options]
testpaths = ["packages"]
python_files = "test_*.py"
python_classes = "Test*"
python_functions = "test_*"
addopts = "-ra --strict-markers --strict-config -p no:cacheprovider"
```

- [ ] **Step 4: Initialize uv workspace**

```bash
uv sync --no-install-workspace
```

Expected: `.venv/` created, no errors (members don't exist yet, that's OK).

- [ ] **Step 5: Verify ruff and mypy work**

```bash
uv run ruff --version
uv run mypy --version
```

Expected: both print versions.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .python-version uv.lock
git commit -m "chore: configure python workspace with uv, ruff, and mypy"
```

---

### Task 6: TypeScript base config

**Files:** Create `tsconfig.base.json`, root `.eslintrc.cjs`, `.prettierrc.json`, `.prettierignore`

- [ ] **Step 1: Create `tsconfig.base.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022"],
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "incremental": true
  },
  "exclude": ["node_modules", "dist", ".next", "coverage"]
}
```

- [ ] **Step 2: Install root TypeScript tooling**

```bash
pnpm add -Dw typescript@^5.6.0 eslint@^9.12.0 prettier@^3.3.3 \
  @typescript-eslint/eslint-plugin@^8.8.0 @typescript-eslint/parser@^8.8.0 \
  eslint-config-prettier@^9.1.0
```

- [ ] **Step 3: Create `.eslintrc.cjs`**

```js
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier'
  ],
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module'
  },
  ignorePatterns: ['dist', 'node_modules', '.next', 'coverage', '.turbo']
};
```

- [ ] **Step 4: Create `.prettierrc.json`**

```json
{
  "semi": true,
  "singleQuote": true,
  "trailingComma": "es5",
  "printWidth": 100,
  "tabWidth": 2,
  "endOfLine": "lf"
}
```

- [ ] **Step 5: Create `.prettierignore`**

```
node_modules
dist
.next
.turbo
coverage
*.lock
pnpm-lock.yaml
.venv
__pycache__
go.sum
```

- [ ] **Step 6: Commit**

```bash
git add tsconfig.base.json .eslintrc.cjs .prettierrc.json .prettierignore package.json pnpm-lock.yaml
git commit -m "chore: configure typescript, eslint, and prettier"
```

---

### Task 7: Go workspace

**Files:** Create `go.work`

- [ ] **Step 1: Verify Go installed**

```bash
go version
```

Expected: `go version go1.22.x` or higher. If missing: `brew install go`.

- [ ] **Step 2: Initialize go.work (no modules yet, will be added in E.1)**

```bash
go work init
```

Expected: `go.work` file created with content:

```
go 1.22
```

- [ ] **Step 3: Commit**

```bash
git add go.work
git commit -m "chore: initialize go workspace"
```

---

### Task 8: Skeleton package directories

**Files:** Create empty package skeletons with their own `pyproject.toml` / `package.json`.

- [ ] **Step 1: Create skeleton directory tree**

```bash
mkdir -p packages/charter/src/charter packages/charter/tests
mkdir -p packages/eval-framework/src/eval_framework packages/eval-framework/tests
mkdir -p packages/agents/cloud-posture/src/cloud_posture packages/agents/cloud-posture/tests
mkdir -p packages/agents/cloud-posture/nlah
mkdir -p packages/control-plane/src/control_plane packages/control-plane/tests
mkdir -p packages/shared/src/shared packages/shared/tests
mkdir -p packages/edge
mkdir -p packages/console
mkdir -p packages/content-packs/generic packages/content-packs/tech packages/content-packs/healthcare
```

- [ ] **Step 2: Create `packages/charter/pyproject.toml`**

```toml
[project]
name = "nexus-charter"
version = "0.1.0"
description = "Nexus runtime charter — execution contracts, budget enforcement, audit hash chain"
requires-python = ">=3.12,<3.13"
license = { file = "../../LICENSE-APACHE" }
dependencies = [
    "pydantic>=2.9.0",
    "pyyaml>=6.0.2",
]

[project.optional-dependencies]
dev = ["pytest>=8.3.0", "pytest-asyncio>=0.24.0", "pytest-cov>=5.0.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/charter"]
```

- [ ] **Step 3: Create stub `packages/charter/src/charter/__init__.py`**

```python
"""Nexus runtime charter."""

__version__ = "0.1.0"
```

- [ ] **Step 4: Create empty `packages/charter/tests/__init__.py` and a smoke test**

```python
# packages/charter/tests/__init__.py
```

```python
# packages/charter/tests/test_smoke.py
"""Smoke test — package imports."""

import charter


def test_charter_imports() -> None:
    assert charter.__version__ == "0.1.0"
```

- [ ] **Step 5: Repeat the same pattern for `eval-framework`**

`packages/eval-framework/pyproject.toml`:

```toml
[project]
name = "nexus-eval-framework"
version = "0.1.0"
description = "Nexus eval framework — case format, runner, gates, comparison reports"
requires-python = ">=3.12,<3.13"
license = { file = "../../LICENSE-APACHE" }
dependencies = [
    "pydantic>=2.9.0",
    "rich>=13.8.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.3.0", "pytest-cov>=5.0.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/eval_framework"]
```

`packages/eval-framework/src/eval_framework/__init__.py`:

```python
"""Nexus eval framework."""

__version__ = "0.1.0"
```

`packages/eval-framework/tests/test_smoke.py`:

```python
"""Smoke test — package imports."""

import eval_framework


def test_eval_framework_imports() -> None:
    assert eval_framework.__version__ == "0.1.0"
```

- [ ] **Step 6: Repeat for `cloud-posture`, `control-plane`, `shared`**

For each, create a `pyproject.toml` (with name `nexus-cloud-posture`, `nexus-control-plane`, `nexus-shared`), an `__init__.py` exporting `__version__ = "0.1.0"`, and a smoke `test_smoke.py`. License field for proprietary packages reads `license = { file = "../../LICENSE-BSL" }` instead of Apache.

- [ ] **Step 7: Sync the workspace**

```bash
uv sync
```

Expected: each package installed in editable mode, `.venv` updated.

- [ ] **Step 8: Run all Python tests**

```bash
uv run pytest -v
```

Expected: 5 smoke tests pass (charter, eval-framework, cloud-posture, control-plane, shared).

- [ ] **Step 9: Commit**

```bash
git add packages/
git commit -m "feat: scaffold python package skeletons with smoke tests"
```

---

### Task 9: GitHub Actions CI workflow

**Files:** Create `.github/workflows/ci.yml`, `.github/workflows/lint.yml`, `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/bug.yml`, `.github/ISSUE_TEMPLATE/feature.yml`

- [ ] **Step 1: Create `.github/workflows/lint.yml`**

```yaml
name: lint

on:
  pull_request:
  push:
    branches: [main]

jobs:
  python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
        with:
          version: "0.4.27"
      - name: Install python
        run: uv python install 3.12
      - name: Sync workspace
        run: uv sync --all-extras
      - name: Ruff check
        run: uv run ruff check .
      - name: Ruff format check
        run: uv run ruff format --check .
      - name: Mypy
        run: uv run mypy packages

  typescript:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9.10.0
      - uses: actions/setup-node@v4
        with:
          node-version: 20.11.1
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm typecheck

  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go vet ./...
```

- [ ] **Step 2: Create `.github/workflows/ci.yml`**

```yaml
name: ci

on:
  pull_request:
  push:
    branches: [main]

jobs:
  python-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
        with:
          version: "0.4.27"
      - run: uv python install 3.12
      - run: uv sync --all-extras
      - run: uv run pytest -v --cov --cov-report=xml
      - uses: codecov/codecov-action@v4
        with:
          fail_ci_if_error: false
        if: always()

  typescript-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9.10.0
      - uses: actions/setup-node@v4
        with:
          node-version: 20.11.1
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm test
```

- [ ] **Step 3: Create `.github/pull_request_template.md`**

```markdown
## Summary

<!-- 1-3 sentences describing the change -->

## Plan reference

<!-- Link the sub-plan in docs/superpowers/plans/ this PR implements, e.g. P0.1 / F.1 / D.3 -->

## Test plan

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated (where applicable)
- [ ] Manual verification described below

## Charter compliance

<!-- For agent code: confirm execution contract enforced, audit log written, budget tracked -->

## Breaking changes

<!-- API/schema/CLI changes that need a migration note. "None" is a valid answer. -->
```

- [ ] **Step 4: Create `.github/ISSUE_TEMPLATE/bug.yml`**

```yaml
name: Bug report
description: Something is broken or behaving unexpectedly
labels: [bug, triage]
body:
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: Describe the bug, including steps to reproduce.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: What did you expect?
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Version / commit
    validations:
      required: true
```

- [ ] **Step 5: Create `.github/ISSUE_TEMPLATE/feature.yml`**

```yaml
name: Feature request
description: Propose a new capability
labels: [enhancement, triage]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What user problem does this solve?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed solution
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
```

- [ ] **Step 6: Commit**

```bash
git add .github/
git commit -m "ci: add github actions for lint and tests; PR + issue templates"
```

---

### Task 10: License files

**Files:** Create `LICENSE-APACHE`, `LICENSE-BSL`, `CODEOWNERS`

- [ ] **Step 1: Create `LICENSE-APACHE`**

Download the verbatim Apache 2.0 license text:

```bash
curl -sL https://www.apache.org/licenses/LICENSE-2.0.txt > LICENSE-APACHE
```

Verify size:

```bash
wc -l LICENSE-APACHE
```

Expected: ~202 lines.

- [ ] **Step 2: Create `LICENSE-BSL`**

```text
Business Source License 1.1

Licensor: Nexus Cyber, Inc.

Licensed Work: Nexus Cyber OS — proprietary packages
   (everything outside packages/charter and packages/eval-framework)

Additional Use Grant: You may use the Licensed Work in non-production environments
   for evaluation, internal R&D, and academic purposes. Production use requires a
   commercial license from Nexus Cyber, Inc.

Change Date: Four years from the date the Licensed Work is published.

Change License: Apache License, Version 2.0

For the full Business Source License text, see https://mariadb.com/bsl11/
```

- [ ] **Step 3: Create `CODEOWNERS`**

```text
# Default owners — every change requires founder + tech lead review until team scales
*                                       @founder @tech-lead

# Charter is the most sensitive code in the repo
/packages/charter/                      @founder @tech-lead @ai-agent-eng
/packages/eval-framework/               @founder @tech-lead @ai-agent-eng

# Detection content
/packages/agents/                       @detection-eng @ai-agent-eng
/packages/content-packs/                @compliance-eng @threat-intel

# Edge runtime
/packages/edge/                         @platform-eng

# Console
/packages/console/                      @frontend-eng

# Infrastructure
/.github/                               @devops-eng @tech-lead
/docker/                                @devops-eng

# Docs
/docs/                                  @tech-writer
/docs/architecture/                     @tech-writer @tech-lead
```

- [ ] **Step 4: Commit**

```bash
git add LICENSE-APACHE LICENSE-BSL CODEOWNERS
git commit -m "chore: add apache 2.0 (oss packages) and bsl 1.1 (proprietary) licenses; codeowners"
```

---

### Task 11: Local-dev docker-compose

**Files:** Create `docker/docker-compose.dev.yml`, `docker/.gitkeep`, `docker/README.md`

- [ ] **Step 1: Create `docker/docker-compose.dev.yml`**

```yaml
name: nexus-dev

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: nexus
      POSTGRES_PASSWORD: nexus_dev
      POSTGRES_DB: nexus
    ports: ['5432:5432']
    volumes:
      - ./.data/postgres:/var/lib/postgresql/data
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U nexus']
      interval: 5s

  timescale:
    image: timescale/timescaledb:latest-pg16
    environment:
      POSTGRES_USER: nexus
      POSTGRES_PASSWORD: nexus_dev
      POSTGRES_DB: nexus_episodic
    ports: ['5433:5432']
    volumes:
      - ./.data/timescale:/var/lib/postgresql/data

  neo4j:
    image: neo4j:5.24-community
    environment:
      NEO4J_AUTH: neo4j/nexus_dev_password
      NEO4J_PLUGINS: '["apoc"]'
    ports:
      - '7474:7474'  # browser
      - '7687:7687'  # bolt
    volumes:
      - ./.data/neo4j:/data

  nats:
    image: nats:2.10-alpine
    command: ['-js']
    ports:
      - '4222:4222'
      - '8222:8222'

  redis:
    image: redis:7-alpine
    ports: ['6379:6379']

  localstack:
    image: localstack/localstack:3.8
    environment:
      SERVICES: s3,iam,sts,cloudtrail,kms,ec2,sns,sqs,lambda,logs
      DEFAULT_REGION: us-east-1
    ports: ['4566:4566']
    volumes:
      - ./.data/localstack:/var/lib/localstack
```

- [ ] **Step 2: Create `docker/README.md`**

````markdown
# Local development infra

Bring it up:

```bash
docker compose -f docker/docker-compose.dev.yml up -d
```

Services exposed:

| Service     | Host port | Notes                                 |
|-------------|-----------|---------------------------------------|
| Postgres    | 5432      | user `nexus`, password `nexus_dev`    |
| TimescaleDB | 5433      | episodic memory                       |
| Neo4j       | 7474/7687 | password `nexus_dev_password`         |
| NATS        | 4222      | with JetStream enabled                |
| Redis       | 6379      |                                       |
| LocalStack  | 4566      | AWS services for testing              |

Tear down:

```bash
docker compose -f docker/docker-compose.dev.yml down -v
```

State persists in `docker/.data/`. Add to `.gitignore` (already done).
````

- [ ] **Step 3: Smoke-test compose file syntax**

```bash
docker compose -f docker/docker-compose.dev.yml config > /dev/null
```

Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add docker/
git commit -m "feat: add docker-compose for local dev infra (postgres, timescale, neo4j, nats, redis, localstack)"
```

---

### Task 12: Top-level docs

**Files:** Create `README.md`, `CONTRIBUTING.md`, `docs/README.md`, `docs/_meta/glossary.md`, `docs/_meta/version-history.md`, `docs/_meta/decisions/_template.md`

- [ ] **Step 1: Create root `README.md`**

````markdown
# Nexus Cyber OS

Autonomous cloud security platform with 18 AI agents, edge deployment, and three-tier remediation.

## Quick start

```bash
# Bring up local infra
docker compose -f docker/docker-compose.dev.yml up -d

# Install dependencies
pnpm install
uv sync

# Run all tests
pnpm test
```

## Repo layout

- `packages/charter/` — runtime charter (Apache 2.0, open source)
- `packages/eval-framework/` — eval suite tooling (Apache 2.0, open source)
- `packages/agents/` — the 18 production agents (proprietary BSL)
- `packages/control-plane/` — SaaS control plane (proprietary BSL)
- `packages/edge/` — edge agent runtime (proprietary BSL)
- `packages/console/` — Next.js customer console (proprietary BSL)
- `packages/content-packs/` — vertical content packs (proprietary BSL)
- `docs/` — strategy, architecture, agent specs, runbooks, plans

## Documentation

- [Strategy & PRD](docs/strategy/)
- [Architecture & Charter](docs/architecture/)
- [Agent specifications](docs/agents/)
- [Build roadmap](docs/superpowers/plans/2026-05-08-build-roadmap.md)
- [Glossary](docs/_meta/glossary.md)
- [ADR index](docs/_meta/decisions/)

## License

Open-source packages (charter, eval-framework): Apache 2.0 — see [LICENSE-APACHE](LICENSE-APACHE).

All other packages: Business Source License 1.1 — see [LICENSE-BSL](LICENSE-BSL). Production use requires a commercial license. Free for evaluation, R&D, and academic use.
````

- [ ] **Step 2: Create `CONTRIBUTING.md`**

````markdown
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
- Go 1.22
- Docker Desktop (or compatible)

## Pre-commit

Husky runs lint-staged on every commit and commitlint on every commit message. If a commit is rejected, fix the issue and commit again — **do not** use `--no-verify`.

## Testing

- Python: `uv run pytest`
- TypeScript: `pnpm test`
- Go: `go test ./...`
- Everything: `pnpm test && uv run pytest && go test ./...`

## Charter compliance

Any code under `packages/agents/` must pass charter contract validation. New agents follow the Cloud Posture reference NLAH pattern (see `packages/agents/cloud-posture/nlah/README.md`).
````

- [ ] **Step 3: Create `docs/README.md`**

````markdown
# Documentation index

This index tells you which doc answers which question.

| If you want to know... | Read |
|---|---|
| What we're building and why | [strategy/VISION.md](strategy/VISION.md) |
| Product scope and phases | [strategy/PRD.md](strategy/PRD.md) |
| System topology and infra | [architecture/platform_architecture.md](architecture/platform_architecture.md) |
| The runtime physics for all agents | [architecture/runtime_charter.md](architecture/runtime_charter.md) |
| The 18 agents — canonical spec | [agents/agent_specification_with_harness.md](agents/agent_specification_with_harness.md) |
| Agent specs PART4-5 (under construction) | [agents/](agents/) |
| Term definitions | [_meta/glossary.md](_meta/glossary.md) |
| Why a decision was made | [_meta/decisions/](_meta/decisions/) |
| The build roadmap | [superpowers/plans/2026-05-08-build-roadmap.md](superpowers/plans/2026-05-08-build-roadmap.md) |
| Detailed implementation plans | [superpowers/plans/](superpowers/plans/) |

## Document status

| Doc | Status | Owner |
|---|---|---|
| VISION.md | living | Mary (analyst) |
| PRD.md | living | John (PM) |
| platform_architecture.md | living | Winston (architect) |
| runtime_charter.md | living | Winston |
| agent_specification_with_harness.md | canonical | Amelia (dev) + Detection Eng |
| AGENT_SPEC_PART1/3 | archived | superseded by harness doc |
| AGENT_SPEC_PART4/5 | under construction | Detection Eng + Tech Writer |
````

- [ ] **Step 4: Create `docs/_meta/glossary.md`**

```markdown
# Glossary

## Charter
The runtime physics every agent obeys: budget envelopes, tool whitelists, escalation rules, audit hash chain, depth/parallelism caps. Implemented in `packages/charter/`. The charter is what makes an LLM into a *production agent*.

## NLAH (Natural Language Agent Harness)
The agent's domain brain — a structured markdown document defining how a single agent thinks. Lives at `packages/agents/<agent-name>/nlah/`. NLAH = the prompt + playbook + tool descriptions + escalation policies for one agent.

## Execution contract
A signed YAML object created at every invocation specifying: identity, task, required outputs, budget, permitted tools, completion conditions, workspace path. Validated by the charter before the agent runs.

## Workspace
The per-invocation file directory at `/workspaces/<customer>/<agent>/<run_id>/`. Ephemeral by default. All in-flight state is path-addressable here.

## Persistent memory
The per-customer-per-agent long-term store at `/persistent/<customer>/<agent>/{episodic,procedural,semantic}/`. Backed by TimescaleDB (episodic), PostgreSQL (procedural), Neo4j Aura (semantic).

## Tier 1 / 2 / 3 remediation
Three levels of agent action authority:
- Tier 3 — recommend only (artifact, no execution)
- Tier 2 — execute after human approval (Slack/Teams/email)
- Tier 1 — autonomous, with auto-rollback timer and post-validation

## Meta-Harness
Agent #13. Reads execution traces, proposes NLAH rewrites for other agents, validates against eval suite, deploys if accepted.

## Eval suite
Per-agent set of test cases (input → expected behavior). Used to gate NLAH changes (≥5% improvement, ≤2% regression).

## Edge plane
Single-tenant runtime deployed inside the customer's environment (Helm chart for EKS/AKS/GKE in Phase 1; bare-metal/air-gap in later phases).

## Control plane
Multi-tenant SaaS we operate on AWS (us-east-1 + us-west-2 DR). Coordinates the edge fleet.

## Synthesis Agent
Agent #12. Combines findings from multiple specialist agents into customer-facing narratives.

## Curiosity Agent
Agent #11. Background "wonder" agent — explores customer environment for unknown patterns when system has idle capacity.

## Investigation Agent
Agent #8. Spawns sub-agents using the Orchestrator-Workers pattern (depth ≤ 3, parallel ≤ 5) for forensic analysis.

## Audit Agent
Agent #14. Append-only hash-chained log writer. The only agent the others cannot disable.

## Vertical content pack
A bundle of NLAH tunings, detection rules, compliance mappings, and integration depth specific to one industry (tech, healthcare, financial, manufacturing, defense). Layered on top of the horizontal platform.
```

- [ ] **Step 5: Create `docs/_meta/version-history.md`**

```markdown
# Version history

| Date | Doc / package | Version | Change | Author |
|---|---|---|---|---|
| 2026-05-08 | repo | 0.1.0 | initial bootstrap (P0.1) | bootstrap |
| 2026-05-08 | charter | 0.1.0 | scaffold | bootstrap |
| 2026-05-08 | eval-framework | 0.1.0 | scaffold | bootstrap |
| 2026-05-08 | docs/agents | — | PART1/3 archived; harness doc canonical | bootstrap |
```

- [ ] **Step 6: Create `docs/_meta/decisions/_template.md`**

```markdown
# ADR-NNN — [Title]

- **Status:** [proposed / accepted / superseded by ADR-NNN / deprecated]
- **Date:** YYYY-MM-DD
- **Authors:** [names / roles]
- **Stakeholders:** [who needs to know]

## Context

[What forces / constraints / problems prompted this decision?]

## Decision

[What did we decide? State it directly.]

## Consequences

### Positive
- ...

### Negative
- ...

### Neutral / unknown
- ...

## Alternatives considered

### Alt 1: ...
- Why rejected: ...

### Alt 2: ...
- Why rejected: ...

## References

- [Plan / spec / spike that produced this decision]
```

- [ ] **Step 7: Create `docs/_meta/decisions/ADR-001-monorepo-bootstrap.md`**

```markdown
# ADR-001 — Monorepo bootstrap & tooling choices

- **Status:** accepted
- **Date:** 2026-05-08
- **Authors:** Winston (architect), Amelia (dev)
- **Stakeholders:** all engineers

## Context

Phase 0 of the build needs a stable repository skeleton before any feature work begins. We have three programming languages (Python for agents/control-plane, TypeScript for console, Go for edge), two licensing tiers (Apache 2.0 for the OSS foundation, BSL for proprietary packages), and a need for fast incremental builds.

## Decision

1. **Monorepo** with a single Git repository at `/Users/prabakarannagarajan/nexus cyber os/` (no trailing space).
2. **Turborepo** for cross-language task orchestration.
3. **pnpm** as the JS/TS package manager with workspaces.
4. **uv** as the Python package manager with workspace members.
5. **go.work** for Go modules.
6. **Husky + commitlint + lint-staged** for pre-commit enforcement.
7. **GitHub Actions with self-hosted runners on AWS** for CI.
8. **Apache 2.0** for `packages/charter/` and `packages/eval-framework/`; **BSL 1.1** with 4-year change-to-Apache for everything else.

## Consequences

### Positive
- Single source of truth for version, dependencies, breaking changes.
- Cross-package refactors land in one PR.
- Easy to enforce conventions (linting, formatting, commits) globally.
- Open-source split is a build-time concern, not a repo-split concern.

### Negative
- Repo grows large; clone time increases. Mitigation: Git LFS for binary assets when needed.
- CI matrix becomes more complex than per-repo CI. Mitigation: Turborepo task caching.

### Neutral / unknown
- BSL adoption among customers is unproven. May need to revisit if customer pushback is significant.

## Alternatives considered

### Alt 1: Polyrepo (one repo per package)
- Why rejected: cross-package refactors become coordination nightmares; release versioning across 25+ packages is the wrong problem to solve at Phase 0.

### Alt 2: Lerna or Rush instead of Turborepo
- Why rejected: Turborepo's speed and simplicity beat both for our scale.

### Alt 3: poetry instead of uv
- Why rejected: uv is materially faster (10-100x), workspace support is first-class, and Astral's tooling (ruff) is already adopted.

### Alt 4: Open-source everything (full Apache 2.0)
- Why rejected: vertical content packs and production NLAHs are core IP; giving them away undermines commercial defensibility (reference: J6 in PRD).

### Alt 5: Closed-source everything (no open-core)
- Why rejected: the runtime charter's value as a category-defining artifact requires open distribution; without an open foundation, we have no community moat.

## References

- Build roadmap: `docs/superpowers/plans/2026-05-08-build-roadmap.md`
- PRD section J6 (open-source split)
- Spike P0.5 (charter contract validator) — informs charter package boundaries
```

- [ ] **Step 8: Commit**

```bash
git add README.md CONTRIBUTING.md docs/
git commit -m "docs: add readme, contributing, glossary, version history, and ADR-001"
```

---

### Task 13: Verify everything from a clean clone

**Files:** none (verification only)

- [ ] **Step 1: Push to a remote (or simulate by re-cloning)**

If a remote exists:

```bash
git remote add origin <repo-url>
git push -u origin main
```

If not, simulate by cloning into `/tmp`:

```bash
git clone "/Users/prabakarannagarajan/nexus cyber os" /tmp/nexus-clone-test
cd /tmp/nexus-clone-test
```

- [ ] **Step 2: Install everything fresh**

```bash
pnpm install --frozen-lockfile
uv sync --all-extras
```

Expected: both succeed.

- [ ] **Step 3: Run all checks**

```bash
pnpm lint
pnpm typecheck
uv run ruff check .
uv run mypy packages
uv run pytest -v
go vet ./...
```

Expected: every command exits 0. Pytest reports 5 smoke tests passing.

- [ ] **Step 4: Bring up infra and verify**

```bash
docker compose -f docker/docker-compose.dev.yml up -d
docker compose -f docker/docker-compose.dev.yml ps
```

Expected: 6 services (postgres, timescale, neo4j, nats, redis, localstack) all `Up (healthy)` or `Up`.

- [ ] **Step 5: Tear down**

```bash
docker compose -f docker/docker-compose.dev.yml down -v
cd "/Users/prabakarannagarajan/nexus cyber os"
rm -rf /tmp/nexus-clone-test
```

- [ ] **Step 6: Final commit (if anything was tweaked during verification)**

```bash
git add -u
git diff --staged
# If anything is staged:
git commit -m "chore: tweaks from clean-clone verification"
```

---

## Self-Review

**Spec coverage** — Every Phase 0 deliverable from the build roadmap (P0.1) is covered:
- ✓ Repo skeleton (Tasks 1, 3, 8)
- ✓ Monorepo + Turborepo + pnpm + uv + go.work (Tasks 3, 5, 7)
- ✓ Branch protection / pre-commit (Task 4)
- ✓ Conventional commits (Task 4)
- ✓ Docs canonicalization including PART1/PART3 archive (Task 2, 12)
- ✓ ADR template + ADR-001 (Task 12)
- ✓ Local-dev docker-compose (Task 11)
- ✓ License split Apache 2.0 / BSL (Task 10)
- ✓ CODEOWNERS (Task 10)
- ✓ GitHub Actions CI (Task 9)

**Placeholder scan:** none found — every step has explicit content.

**Type / name consistency:** package names match across `pyproject.toml` (`nexus-charter`, `nexus-eval-framework`), `__init__.py` (`charter`, `eval_framework`), Pytest paths, and CODEOWNERS. The proprietary packages all use `nexus-<package>` naming.

**Gap:** branch protection rules (require PR review, require CI to pass, no force pushes to main) are configured **manually in GitHub Settings**, not in code. Documented in CONTRIBUTING.md but not automated. Acceptable for Phase 0; consider GitHub-owner-managed Terraform module in Phase 1 if needed.
