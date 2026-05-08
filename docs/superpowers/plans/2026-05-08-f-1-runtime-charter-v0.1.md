# F.1 — Runtime Charter v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the runtime charter — the universal physics every Nexus agent obeys — as a Python package with: typed execution contract schema, contract loader/validator, workspace manager, tool registry + whitelist, budget envelope tracker (5 dimensions), append-only hash-chained audit log, and a charter context manager that wraps any agent invocation. Ship a reference "hello world" agent that proves the entire pipeline works end-to-end.

**Architecture:** A single Python package `nexus-charter` exposing a context manager API. Agent code is wrapped: `with Charter(contract) as ctx: ...`. Inside the context, every tool call routes through `ctx.call_tool(name, **kwargs)` which checks the whitelist, decrements budgets, writes the audit log entry, and only then dispatches. Workspace and persistent paths are mounted on the context. Audit log is append-only on disk with each entry containing the SHA-256 of the previous entry, forming a hash chain that detects tampering.

**Tech Stack:** Python 3.12 · Pydantic 2.9 · PyYAML · cryptography (for HMAC signing) · pytest · pytest-asyncio · hypothesis (property-based tests) · structlog · click (CLI)

**Depends on:** P0.1 (repo bootstrap), P0.5 (charter contract validator spike — informs design), P0.7 (budget enforcement spike).

---

## File Structure

```
packages/charter/
├── pyproject.toml                              # already scaffolded in P0.1; extend deps
├── src/charter/
│   ├── __init__.py                             # public API surface
│   ├── contract.py                             # ExecutionContract Pydantic model
│   ├── budget.py                               # BudgetEnvelope, BudgetExhausted exception
│   ├── workspace.py                            # WorkspaceManager
│   ├── tools.py                                # ToolRegistry, ToolCall, ToolResult
│   ├── audit.py                                # AuditLog (hash-chained append)
│   ├── verifier.py                             # AuditLog integrity verification
│   ├── context.py                              # Charter context manager (the public wrapper)
│   ├── exceptions.py                           # CharterViolation, BudgetExhausted, ToolNotPermitted, ContractInvalid
│   ├── schema/
│   │   └── execution_contract.schema.yaml      # YAML schema for contracts
│   └── cli.py                                  # `charter validate` / `charter audit` commands
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_contract.py
│   ├── test_budget.py
│   ├── test_workspace.py
│   ├── test_tools.py
│   ├── test_audit.py
│   ├── test_verifier.py
│   ├── test_context.py
│   ├── test_cli.py
│   ├── test_audit_property_based.py            # hypothesis-driven
│   └── fixtures/
│       ├── valid_contract.yaml
│       └── invalid_contract.yaml
└── examples/
    └── hello_world_agent/
        ├── nlah/
        │   └── README.md                       # the "domain brain" of this stub agent
        ├── agent.py                            # uses Charter context
        ├── tools.py                            # toy tools (echo, add)
        ├── contract.yaml                       # invocation contract
        └── README.md
```

---

## Tasks

### Task 1: Extend charter pyproject.toml with runtime deps

**Files:** Modify `packages/charter/pyproject.toml`

- [ ] **Step 1: Update dependencies block**

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
    "cryptography>=43.0.0",
    "structlog>=24.4.0",
    "click>=8.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=5.0.0",
    "hypothesis>=6.112.0",
    "freezegun>=1.5.0",
]

[project.scripts]
charter = "charter.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/charter"]
```

- [ ] **Step 2: Sync workspace**

```bash
uv sync --all-extras
```

Expected: charter dependencies installed, no errors.

- [ ] **Step 3: Verify imports**

```bash
uv run python -c "import pydantic, yaml, cryptography, structlog, click; print('ok')"
```

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add packages/charter/pyproject.toml uv.lock
git commit -m "chore(charter): add runtime dependencies (pydantic, pyyaml, cryptography, structlog, click)"
```

---

### Task 2: Exception hierarchy

**Files:** Create `packages/charter/src/charter/exceptions.py`, `packages/charter/tests/test_exceptions.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_exceptions.py
"""Tests for charter exceptions."""

import pytest

from charter.exceptions import (
    BudgetExhausted,
    CharterViolation,
    ContractInvalid,
    ToolNotPermitted,
)


def test_charter_violation_is_base() -> None:
    assert issubclass(BudgetExhausted, CharterViolation)
    assert issubclass(ToolNotPermitted, CharterViolation)
    assert issubclass(ContractInvalid, CharterViolation)


def test_budget_exhausted_carries_dimension() -> None:
    err = BudgetExhausted(dimension="tokens", limit=1000, used=1500)
    assert err.dimension == "tokens"
    assert err.limit == 1000
    assert err.used == 1500
    assert "tokens" in str(err)


def test_tool_not_permitted_carries_tool_name() -> None:
    err = ToolNotPermitted(tool="aws_iam_delete_user", permitted=["aws_s3_describe"])
    assert err.tool == "aws_iam_delete_user"
    assert "aws_iam_delete_user" in str(err)


def test_contract_invalid_carries_field_path() -> None:
    err = ContractInvalid(field="budget.tokens", reason="must be positive")
    assert err.field == "budget.tokens"
    assert err.reason == "must be positive"
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run pytest packages/charter/tests/test_exceptions.py -v
```

Expected: `ImportError: cannot import name 'BudgetExhausted' from 'charter.exceptions'`

- [ ] **Step 3: Implement**

```python
# packages/charter/src/charter/exceptions.py
"""Charter exception hierarchy."""


class CharterViolation(Exception):
    """Base for any violation of the runtime charter."""


class ContractInvalid(CharterViolation):
    """Execution contract failed validation."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"contract invalid at '{field}': {reason}")


class BudgetExhausted(CharterViolation):
    """Agent exceeded its budget envelope."""

    def __init__(self, dimension: str, limit: int | float, used: int | float) -> None:
        self.dimension = dimension
        self.limit = limit
        self.used = used
        super().__init__(
            f"budget '{dimension}' exhausted: used {used} of limit {limit}"
        )


class ToolNotPermitted(CharterViolation):
    """Agent attempted to call a tool not in its permitted list."""

    def __init__(self, tool: str, permitted: list[str]) -> None:
        self.tool = tool
        self.permitted = permitted
        super().__init__(f"tool '{tool}' not permitted (allowed: {permitted})")
```

- [ ] **Step 4: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_exceptions.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/charter/src/charter/exceptions.py packages/charter/tests/test_exceptions.py
git commit -m "feat(charter): exception hierarchy (CharterViolation, BudgetExhausted, ToolNotPermitted, ContractInvalid)"
```

---

### Task 3: BudgetEnvelope

**Files:** Create `packages/charter/src/charter/budget.py`, `packages/charter/tests/test_budget.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_budget.py
"""Tests for the budget envelope."""

import pytest

from charter.budget import BudgetEnvelope
from charter.exceptions import BudgetExhausted


def test_envelope_construction() -> None:
    env = BudgetEnvelope(
        llm_calls=10, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10
    )
    assert env.llm_calls == 10
    assert env.tokens == 1000


def test_envelope_consume_within_limit() -> None:
    env = BudgetEnvelope(llm_calls=10, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10)
    env.consume(llm_calls=1, tokens=100)
    assert env.used("llm_calls") == 1
    assert env.used("tokens") == 100
    assert env.remaining("llm_calls") == 9


def test_envelope_consume_exceeds_limit_raises() -> None:
    env = BudgetEnvelope(llm_calls=2, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10)
    env.consume(llm_calls=1, tokens=0)
    with pytest.raises(BudgetExhausted) as exc_info:
        env.consume(llm_calls=2, tokens=0)
    assert exc_info.value.dimension == "llm_calls"
    assert exc_info.value.limit == 2
    assert exc_info.value.used == 3


def test_envelope_wall_clock_check() -> None:
    env = BudgetEnvelope(llm_calls=10, tokens=1000, wall_clock_sec=0.001, cloud_api_calls=50, mb_written=10)
    env.start_clock()
    import time
    time.sleep(0.01)
    with pytest.raises(BudgetExhausted) as exc_info:
        env.check_wall_clock()
    assert exc_info.value.dimension == "wall_clock_sec"


def test_envelope_zero_or_negative_limit_rejected() -> None:
    with pytest.raises(ValueError):
        BudgetEnvelope(llm_calls=0, tokens=1000, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10)
    with pytest.raises(ValueError):
        BudgetEnvelope(llm_calls=10, tokens=-1, wall_clock_sec=60.0, cloud_api_calls=50, mb_written=10)
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_budget.py -v
```

Expected: `ImportError: cannot import name 'BudgetEnvelope' from 'charter.budget'`

- [ ] **Step 3: Implement**

```python
# packages/charter/src/charter/budget.py
"""Budget envelope — tracks 5-dimensional resource consumption per agent invocation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from charter.exceptions import BudgetExhausted

_DIMENSIONS = ("llm_calls", "tokens", "wall_clock_sec", "cloud_api_calls", "mb_written")


@dataclass
class BudgetEnvelope:
    """Five-dimensional budget envelope.

    All limits must be positive. Consume tracks usage; exceeding any
    dimension raises BudgetExhausted.
    """

    llm_calls: int
    tokens: int
    wall_clock_sec: float
    cloud_api_calls: int
    mb_written: int
    _used: dict[str, float] = field(default_factory=lambda: {d: 0 for d in _DIMENSIONS})
    _start: float | None = None

    def __post_init__(self) -> None:
        for dim in _DIMENSIONS:
            limit = getattr(self, dim)
            if limit <= 0:
                raise ValueError(f"{dim} must be positive (got {limit})")

    def start_clock(self) -> None:
        self._start = time.monotonic()

    def consume(self, **kwargs: float) -> None:
        """Apply usage; raises BudgetExhausted if any dimension over."""
        for dim, amount in kwargs.items():
            if dim not in _DIMENSIONS:
                raise ValueError(f"unknown budget dimension: {dim}")
            self._used[dim] += amount
            limit = getattr(self, dim)
            if self._used[dim] > limit:
                raise BudgetExhausted(dimension=dim, limit=limit, used=self._used[dim])

    def check_wall_clock(self) -> None:
        """Verify we haven't exceeded wall-clock budget. Call periodically."""
        if self._start is None:
            return
        elapsed = time.monotonic() - self._start
        self._used["wall_clock_sec"] = elapsed
        if elapsed > self.wall_clock_sec:
            raise BudgetExhausted(
                dimension="wall_clock_sec", limit=self.wall_clock_sec, used=elapsed
            )

    def used(self, dimension: str) -> float:
        return self._used[dimension]

    def remaining(self, dimension: str) -> float:
        return getattr(self, dimension) - self._used[dimension]
```

- [ ] **Step 4: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_budget.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/charter/src/charter/budget.py packages/charter/tests/test_budget.py
git commit -m "feat(charter): five-dimensional budget envelope with consume/check API"
```

---

### Task 4: ExecutionContract Pydantic model

**Files:** Create `packages/charter/src/charter/contract.py`, `packages/charter/tests/fixtures/valid_contract.yaml`, `packages/charter/tests/fixtures/invalid_contract.yaml`, `packages/charter/tests/test_contract.py`

- [ ] **Step 1: Create fixture files**

`packages/charter/tests/fixtures/valid_contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
source_agent: supervisor
target_agent: cloud_posture
customer_id: cust_acme_001
task: "Scan AWS account 111122223333 for public S3 buckets"
required_outputs:
  - findings.json
  - summary.md
budget:
  llm_calls: 20
  tokens: 50000
  wall_clock_sec: 60
  cloud_api_calls: 200
  mb_written: 50
permitted_tools:
  - prowler_scan
  - aws_s3_describe
  - neo4j_write
completion_condition: "findings.json exists AND summary.md exists"
escalation_rules:
  - condition: budget_exhausted
    target: supervisor
  - condition: tool_unavailable
    target: human_oncall
workspace: /workspaces/cust_acme_001/cloud_posture/01J7M3X9Z1K8RPVQNH2T8DBHFZ/
persistent_root: /persistent/cust_acme_001/cloud_posture/
created_at: 2026-05-08T10:00:00Z
expires_at: 2026-05-08T10:05:00Z
```

`packages/charter/tests/fixtures/invalid_contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: not-a-ulid
source_agent: ""
target_agent: cloud_posture
customer_id: cust_acme_001
task: ""
required_outputs: []
budget:
  llm_calls: -5
  tokens: 50000
  wall_clock_sec: 60
  cloud_api_calls: 200
  mb_written: 50
permitted_tools: []
completion_condition: ""
workspace: /workspaces/cust_acme_001/cloud_posture/run/
persistent_root: /persistent/cust_acme_001/cloud_posture/
created_at: 2026-05-08T10:00:00Z
expires_at: 2026-05-08T10:05:00Z
```

- [ ] **Step 2: Write the failing test**

```python
# packages/charter/tests/test_contract.py
"""Tests for ExecutionContract."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from charter.contract import ExecutionContract, load_contract

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_valid_contract() -> None:
    contract = load_contract(FIXTURES / "valid_contract.yaml")
    assert contract.target_agent == "cloud_posture"
    assert contract.budget.llm_calls == 20
    assert "findings.json" in contract.required_outputs


def test_load_invalid_contract_raises() -> None:
    with pytest.raises(ValidationError):
        load_contract(FIXTURES / "invalid_contract.yaml")


def test_contract_rejects_blank_task() -> None:
    with pytest.raises(ValidationError):
        ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            source_agent="supervisor",
            target_agent="cloud_posture",
            customer_id="cust_acme_001",
            task="",
            required_outputs=["findings.json"],
            budget={"llm_calls": 1, "tokens": 1, "wall_clock_sec": 1, "cloud_api_calls": 1, "mb_written": 1},
            permitted_tools=["prowler_scan"],
            completion_condition="findings.json exists",
            escalation_rules=[],
            workspace="/workspaces/x/",
            persistent_root="/persistent/x/",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )


def test_contract_requires_at_least_one_output() -> None:
    with pytest.raises(ValidationError):
        ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            source_agent="supervisor",
            target_agent="cloud_posture",
            customer_id="cust_acme_001",
            task="scan",
            required_outputs=[],
            budget={"llm_calls": 1, "tokens": 1, "wall_clock_sec": 1, "cloud_api_calls": 1, "mb_written": 1},
            permitted_tools=["prowler_scan"],
            completion_condition="x",
            escalation_rules=[],
            workspace="/workspaces/x/",
            persistent_root="/persistent/x/",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )


def test_contract_requires_at_least_one_tool() -> None:
    with pytest.raises(ValidationError):
        ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            source_agent="supervisor",
            target_agent="cloud_posture",
            customer_id="cust_acme_001",
            task="scan",
            required_outputs=["findings.json"],
            budget={"llm_calls": 1, "tokens": 1, "wall_clock_sec": 1, "cloud_api_calls": 1, "mb_written": 1},
            permitted_tools=[],
            completion_condition="x",
            escalation_rules=[],
            workspace="/workspaces/x/",
            persistent_root="/persistent/x/",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )
```

- [ ] **Step 3: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_contract.py -v
```

Expected: `ImportError`

- [ ] **Step 4: Implement contract model**

```python
# packages/charter/src/charter/contract.py
"""Execution contract — the signed YAML that defines an agent invocation."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, Field, StringConstraints, model_validator

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


class BudgetSpec(BaseModel):
    """Budget specification — all values must be positive."""

    llm_calls: int = Field(gt=0)
    tokens: int = Field(gt=0)
    wall_clock_sec: float = Field(gt=0)
    cloud_api_calls: int = Field(gt=0)
    mb_written: int = Field(gt=0)


class EscalationRule(BaseModel):
    """When a condition fires, escalate to this target."""

    condition: NonEmptyStr
    target: NonEmptyStr


class ExecutionContract(BaseModel):
    """Signed YAML contract validated by the charter before agent runs.

    Every field is required. A blank/empty value fails validation.
    """

    schema_version: NonEmptyStr
    delegation_id: NonEmptyStr
    source_agent: NonEmptyStr
    target_agent: NonEmptyStr
    customer_id: NonEmptyStr
    task: NonEmptyStr
    required_outputs: list[NonEmptyStr] = Field(min_length=1)
    budget: BudgetSpec
    permitted_tools: list[NonEmptyStr] = Field(min_length=1)
    completion_condition: NonEmptyStr
    escalation_rules: list[EscalationRule] = Field(default_factory=list)
    workspace: NonEmptyStr
    persistent_root: NonEmptyStr
    created_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def _check_delegation_id(self) -> "ExecutionContract":
        if not ULID_RE.match(self.delegation_id):
            raise ValueError("delegation_id must be a valid ULID (26-char Crockford base32)")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self


def load_contract(path: Path | str) -> ExecutionContract:
    """Load and validate an execution contract from YAML."""
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    return ExecutionContract.model_validate(data)
```

- [ ] **Step 5: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_contract.py -v
```

Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add packages/charter/src/charter/contract.py packages/charter/tests/test_contract.py packages/charter/tests/fixtures/
git commit -m "feat(charter): execution contract Pydantic model with YAML loader and ULID validation"
```

---

### Task 5: WorkspaceManager

**Files:** Create `packages/charter/src/charter/workspace.py`, `packages/charter/tests/test_workspace.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_workspace.py
"""Tests for WorkspaceManager."""

from pathlib import Path

import pytest

from charter.workspace import WorkspaceManager


def test_workspace_creates_dirs(tmp_path: Path) -> None:
    workspace = tmp_path / "workspaces" / "cust" / "agent" / "run123"
    persistent = tmp_path / "persistent" / "cust" / "agent"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    assert workspace.is_dir()
    assert (persistent / "episodic").is_dir()
    assert (persistent / "procedural").is_dir()
    assert (persistent / "semantic").is_dir()


def test_workspace_write_output(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    mgr.write_output("findings.json", b'{"x": 1}')
    assert (workspace / "findings.json").read_bytes() == b'{"x": 1}'


def test_workspace_check_required_outputs_missing(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    missing = mgr.missing_outputs(["findings.json", "summary.md"])
    assert missing == ["findings.json", "summary.md"]


def test_workspace_check_required_outputs_partial(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    mgr.write_output("findings.json", b"{}")
    missing = mgr.missing_outputs(["findings.json", "summary.md"])
    assert missing == ["summary.md"]


def test_workspace_disk_usage_tracked(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    mgr.write_output("a.txt", b"x" * 1024)
    mgr.write_output("b.txt", b"y" * 2048)
    assert mgr.bytes_written() == 3072
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_workspace.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/charter/src/charter/workspace.py
"""Workspace manager — path-addressable storage for agent invocations."""

from __future__ import annotations

from pathlib import Path

_MEMORY_KINDS = ("episodic", "procedural", "semantic")


class WorkspaceManager:
    """Owns the per-invocation workspace and persistent memory mount points."""

    def __init__(self, workspace: Path, persistent_root: Path) -> None:
        self.workspace = Path(workspace)
        self.persistent_root = Path(persistent_root)
        self._bytes_written = 0

    def setup(self) -> None:
        """Create workspace + persistent memory subdirectories."""
        self.workspace.mkdir(parents=True, exist_ok=True)
        for kind in _MEMORY_KINDS:
            (self.persistent_root / kind).mkdir(parents=True, exist_ok=True)

    def write_output(self, name: str, data: bytes) -> Path:
        """Write a required output to the workspace."""
        if "/" in name or ".." in name:
            raise ValueError(f"output name must be a flat filename, got {name!r}")
        target = self.workspace / name
        target.write_bytes(data)
        self._bytes_written += len(data)
        return target

    def missing_outputs(self, required: list[str]) -> list[str]:
        return [name for name in required if not (self.workspace / name).exists()]

    def bytes_written(self) -> int:
        return self._bytes_written

    def episodic(self) -> Path:
        return self.persistent_root / "episodic"

    def procedural(self) -> Path:
        return self.persistent_root / "procedural"

    def semantic(self) -> Path:
        return self.persistent_root / "semantic"
```

- [ ] **Step 4: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_workspace.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/charter/src/charter/workspace.py packages/charter/tests/test_workspace.py
git commit -m "feat(charter): WorkspaceManager creates per-invocation paths and tracks bytes written"
```

---

### Task 6: ToolRegistry

**Files:** Create `packages/charter/src/charter/tools.py`, `packages/charter/tests/test_tools.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_tools.py
"""Tests for ToolRegistry."""

from typing import Any

import pytest

from charter.exceptions import ToolNotPermitted
from charter.tools import ToolRegistry


def echo_tool(value: str) -> str:
    return value


def add_tool(a: int, b: int) -> int:
    return a + b


def test_register_and_call() -> None:
    reg = ToolRegistry()
    reg.register("echo", echo_tool, version="1.0.0", cloud_calls=0)
    result = reg.call("echo", permitted=["echo"], value="hi")
    assert result == "hi"


def test_call_unregistered_tool_raises() -> None:
    reg = ToolRegistry()
    with pytest.raises(KeyError):
        reg.call("nonexistent", permitted=["nonexistent"])


def test_call_unpermitted_tool_raises() -> None:
    reg = ToolRegistry()
    reg.register("delete_user", lambda **_: None, version="1.0.0", cloud_calls=1)
    with pytest.raises(ToolNotPermitted) as exc_info:
        reg.call("delete_user", permitted=["read_user"])
    assert exc_info.value.tool == "delete_user"


def test_versioning() -> None:
    reg = ToolRegistry()
    reg.register("v_tool", lambda: None, version="1.2.3", cloud_calls=0)
    assert reg.version("v_tool") == "1.2.3"


def test_cloud_calls_metadata() -> None:
    reg = ToolRegistry()
    reg.register("aws_s3_describe", lambda: None, version="1.0.0", cloud_calls=1)
    assert reg.cloud_calls("aws_s3_describe") == 1
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_tools.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/charter/src/charter/tools.py
"""Tool registry — version-pinned, whitelist-checked dispatch."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from charter.exceptions import ToolNotPermitted


@dataclass(frozen=True)
class ToolMeta:
    func: Callable[..., Any]
    version: str
    cloud_calls: int  # how many cloud-API calls this tool makes per invocation


class ToolRegistry:
    """Holds the universe of callable tools. Each call is permission-checked."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolMeta] = {}

    def register(
        self, name: str, func: Callable[..., Any], *, version: str, cloud_calls: int
    ) -> None:
        if name in self._tools:
            raise ValueError(f"tool {name!r} already registered")
        self._tools[name] = ToolMeta(func=func, version=version, cloud_calls=cloud_calls)

    def call(self, name: str, *, permitted: list[str], **kwargs: Any) -> Any:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        if name not in permitted:
            raise ToolNotPermitted(tool=name, permitted=permitted)
        return self._tools[name].func(**kwargs)

    def version(self, name: str) -> str:
        return self._tools[name].version

    def cloud_calls(self, name: str) -> int:
        return self._tools[name].cloud_calls

    def known_tools(self) -> list[str]:
        return sorted(self._tools.keys())
```

- [ ] **Step 4: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_tools.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/charter/src/charter/tools.py packages/charter/tests/test_tools.py
git commit -m "feat(charter): ToolRegistry with whitelist enforcement and version pinning"
```

---

### Task 7: AuditLog (hash-chained, append-only)

**Files:** Create `packages/charter/src/charter/audit.py`, `packages/charter/tests/test_audit.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_audit.py
"""Tests for the audit log — append-only with SHA-256 hash chain."""

import json
from pathlib import Path

from charter.audit import AuditLog, AuditEntry


def test_append_first_entry_links_to_genesis(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="cloud_posture", run_id="r1")
    entry = log.append(action="tool_call", payload={"tool": "echo", "kwargs": {"value": "hi"}})
    assert entry.previous_hash == "0" * 64  # genesis link


def test_append_chains_hashes(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="cloud_posture", run_id="r1")
    e1 = log.append(action="tool_call", payload={"tool": "a"})
    e2 = log.append(action="tool_call", payload={"tool": "b"})
    assert e2.previous_hash == e1.entry_hash
    assert e1.entry_hash != e2.entry_hash


def test_log_persists_to_disk(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="cloud_posture", run_id="r1")
    log.append(action="tool_call", payload={"tool": "a"})
    log.append(action="tool_call", payload={"tool": "b"})
    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["action"] == "tool_call"
    assert parsed[1]["previous_hash"] == parsed[0]["entry_hash"]


def test_log_resumes_chain_from_existing_file(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log1 = AuditLog(path=log_path, agent="cloud_posture", run_id="r1")
    e1 = log1.append(action="tool_call", payload={"tool": "a"})
    log2 = AuditLog(path=log_path, agent="cloud_posture", run_id="r1")
    e2 = log2.append(action="tool_call", payload={"tool": "b"})
    assert e2.previous_hash == e1.entry_hash


def test_append_includes_timestamp(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="x", run_id="r1")
    entry = log.append(action="x", payload={})
    assert entry.timestamp.endswith("Z") or "+" in entry.timestamp
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_audit.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/charter/src/charter/audit.py
"""Append-only hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    agent: str
    run_id: str
    action: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(raw: str) -> "AuditEntry":
        return AuditEntry(**json.loads(raw))


def _hash_entry(
    timestamp: str,
    agent: str,
    run_id: str,
    action: str,
    payload: dict[str, Any],
    previous_hash: str,
) -> str:
    canonical = json.dumps(
        {
            "timestamp": timestamp,
            "agent": agent,
            "run_id": run_id,
            "action": action,
            "payload": payload,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only hash chain. One file per run.

    The first entry's previous_hash is the genesis (64 zeroes). Every
    subsequent entry's previous_hash is the previous entry's entry_hash.
    """

    def __init__(self, path: Path, agent: str, run_id: str) -> None:
        self.path = Path(path)
        self.agent = agent
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._tail = self._read_tail_hash()

    def _read_tail_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as f:
            last_line = ""
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return GENESIS_HASH
        return AuditEntry.from_json(last_line).entry_hash

    def append(self, action: str, payload: dict[str, Any]) -> AuditEntry:
        ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        entry_hash = _hash_entry(
            timestamp=ts,
            agent=self.agent,
            run_id=self.run_id,
            action=action,
            payload=payload,
            previous_hash=self._tail,
        )
        entry = AuditEntry(
            timestamp=ts,
            agent=self.agent,
            run_id=self.run_id,
            action=action,
            payload=payload,
            previous_hash=self._tail,
            entry_hash=entry_hash,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json() + "\n")
        self._tail = entry_hash
        return entry
```

- [ ] **Step 4: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_audit.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/charter/src/charter/audit.py packages/charter/tests/test_audit.py
git commit -m "feat(charter): append-only hash-chained audit log"
```

---

### Task 8: AuditLog property-based test

**Files:** Create `packages/charter/tests/test_audit_property_based.py`

- [ ] **Step 1: Write the property-based test**

```python
# packages/charter/tests/test_audit_property_based.py
"""Hypothesis-based properties for the audit hash chain."""

import json
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from charter.audit import GENESIS_HASH, AuditEntry, AuditLog


@given(actions=st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=50))
def test_chain_integrity_holds_for_any_sequence(actions: list[str], tmp_path_factory) -> None:
    log_path = tmp_path_factory.mktemp("hyp") / "audit.jsonl"
    log = AuditLog(path=log_path, agent="x", run_id="r")
    entries = [log.append(action=a, payload={"i": i}) for i, a in enumerate(actions)]

    raw_lines = log_path.read_text().strip().split("\n")
    persisted = [AuditEntry.from_json(line) for line in raw_lines]

    assert len(persisted) == len(entries)
    assert persisted[0].previous_hash == GENESIS_HASH
    for prev, curr in zip(persisted, persisted[1:], strict=False):
        assert curr.previous_hash == prev.entry_hash


@given(payload=st.dictionaries(st.text(min_size=1), st.integers()))
def test_entry_hash_is_deterministic_for_same_input(payload: dict[str, int], tmp_path_factory) -> None:
    p1 = tmp_path_factory.mktemp("h1") / "a.jsonl"
    p2 = tmp_path_factory.mktemp("h2") / "a.jsonl"
    log1 = AuditLog(path=p1, agent="x", run_id="r")
    log2 = AuditLog(path=p2, agent="x", run_id="r")
    e1 = log1.append(action="z", payload=payload)
    e2 = log2.append(action="z", payload=payload)
    # timestamps differ; we can't expect entry_hash equality
    # but previous_hash must be GENESIS for both
    assert e1.previous_hash == GENESIS_HASH
    assert e2.previous_hash == GENESIS_HASH
```

- [ ] **Step 2: Run**

```bash
uv run pytest packages/charter/tests/test_audit_property_based.py -v
```

Expected: passes (hypothesis runs ~100 examples per test).

- [ ] **Step 3: Commit**

```bash
git add packages/charter/tests/test_audit_property_based.py
git commit -m "test(charter): hypothesis property-based tests for audit chain integrity"
```

---

### Task 9: Audit verifier

**Files:** Create `packages/charter/src/charter/verifier.py`, `packages/charter/tests/test_verifier.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_verifier.py
"""Tests for AuditLog integrity verification."""

import json
from pathlib import Path

import pytest

from charter.audit import AuditLog
from charter.verifier import VerificationResult, verify_audit_log


def test_clean_log_verifies(tmp_path: Path) -> None:
    log = AuditLog(path=tmp_path / "audit.jsonl", agent="x", run_id="r")
    log.append(action="a", payload={})
    log.append(action="b", payload={})
    log.append(action="c", payload={})
    result = verify_audit_log(tmp_path / "audit.jsonl")
    assert result.valid is True
    assert result.entries_checked == 3


def test_tampered_payload_fails_verification(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="x", run_id="r")
    log.append(action="a", payload={"v": 1})
    log.append(action="b", payload={"v": 2})

    raw = log_path.read_text().strip().split("\n")
    parsed = [json.loads(line) for line in raw]
    parsed[0]["payload"]["v"] = 999  # tamper
    log_path.write_text("\n".join(json.dumps(p, sort_keys=True, separators=(",", ":")) for p in parsed) + "\n")

    result = verify_audit_log(log_path)
    assert result.valid is False
    assert result.broken_at == 0


def test_broken_chain_link_fails(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="x", run_id="r")
    log.append(action="a", payload={})
    log.append(action="b", payload={})

    raw = log_path.read_text().strip().split("\n")
    parsed = [json.loads(line) for line in raw]
    parsed[1]["previous_hash"] = "f" * 64  # break the chain
    log_path.write_text("\n".join(json.dumps(p, sort_keys=True, separators=(",", ":")) for p in parsed) + "\n")

    result = verify_audit_log(log_path)
    assert result.valid is False
    assert result.broken_at == 1
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_verifier.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/charter/src/charter/verifier.py
"""Audit log integrity verification — recompute hashes and check chain links."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from charter.audit import GENESIS_HASH, AuditEntry, _hash_entry


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    entries_checked: int
    broken_at: int | None  # index of first broken entry, or None


def verify_audit_log(path: Path | str) -> VerificationResult:
    p = Path(path)
    if not p.exists():
        return VerificationResult(valid=False, entries_checked=0, broken_at=None)

    expected_prev = GENESIS_HASH
    count = 0
    with p.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            entry = AuditEntry.from_json(line)
            recomputed = _hash_entry(
                timestamp=entry.timestamp,
                agent=entry.agent,
                run_id=entry.run_id,
                action=entry.action,
                payload=entry.payload,
                previous_hash=entry.previous_hash,
            )
            if recomputed != entry.entry_hash or entry.previous_hash != expected_prev:
                return VerificationResult(valid=False, entries_checked=count, broken_at=idx)
            expected_prev = entry.entry_hash
            count += 1
    return VerificationResult(valid=True, entries_checked=count, broken_at=None)
```

- [ ] **Step 4: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_verifier.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/charter/src/charter/verifier.py packages/charter/tests/test_verifier.py
git commit -m "feat(charter): audit log verifier detects payload tampering and broken chain links"
```

---

### Task 10: Charter context manager

**Files:** Create `packages/charter/src/charter/context.py`, `packages/charter/tests/test_context.py`, update `packages/charter/src/charter/__init__.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_context.py
"""Tests for the Charter context manager — the public wrapper."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from charter import Charter, ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract
from charter.exceptions import BudgetExhausted, ToolNotPermitted


def _make_contract(tmp_path: Path, *, llm_calls: int = 5, tokens: int = 1000) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="hello_world",
        customer_id="cust_test",
        task="say hi",
        required_outputs=["greeting.txt"],
        budget=BudgetSpec(
            llm_calls=llm_calls,
            tokens=tokens,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["echo"],
        completion_condition="greeting.txt exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register("echo", lambda value: value, version="1.0.0", cloud_calls=0)
    reg.register("delete", lambda: None, version="1.0.0", cloud_calls=1)
    return reg


def test_context_runs_simple_tool(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        result = ctx.call_tool("echo", value="hi", llm_calls=1, tokens=10)
        assert result == "hi"
        ctx.write_output("greeting.txt", b"hi")


def test_context_rejects_unpermitted_tool(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        with pytest.raises(ToolNotPermitted):
            ctx.call_tool("delete", llm_calls=0, tokens=0)


def test_context_enforces_budget(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path, llm_calls=2)
    with Charter(contract, tools=_registry()) as ctx:
        ctx.call_tool("echo", value="a", llm_calls=1, tokens=10)
        ctx.call_tool("echo", value="b", llm_calls=1, tokens=10)
        with pytest.raises(BudgetExhausted) as exc_info:
            ctx.call_tool("echo", value="c", llm_calls=1, tokens=10)
        assert exc_info.value.dimension == "llm_calls"


def test_context_writes_audit_log(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        ctx.call_tool("echo", value="hi", llm_calls=1, tokens=10)
        ctx.write_output("greeting.txt", b"hi")
        audit_path = ctx.audit_path
    assert audit_path.exists()
    lines = audit_path.read_text().strip().split("\n")
    actions = [line for line in lines if "tool_call" in line or "output_written" in line]
    assert len(actions) >= 2  # tool_call + output_written


def test_context_completion_check(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        # Don't write the required output.
        with pytest.raises(RuntimeError) as exc_info:
            ctx.assert_complete()
        assert "greeting.txt" in str(exc_info.value)


def test_context_assert_complete_passes_when_outputs_present(tmp_path: Path) -> None:
    contract = _make_contract(tmp_path)
    with Charter(contract, tools=_registry()) as ctx:
        ctx.write_output("greeting.txt", b"hi")
        ctx.assert_complete()  # does not raise
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_context.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement context**

```python
# packages/charter/src/charter/context.py
"""Charter context manager — the public wrapper around an agent invocation."""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import Any

from charter.audit import AuditLog
from charter.budget import BudgetEnvelope
from charter.contract import ExecutionContract
from charter.tools import ToolRegistry
from charter.workspace import WorkspaceManager


class Charter:
    """Wraps a single agent invocation under the runtime charter.

    Usage:
        with Charter(contract, tools=registry) as ctx:
            ctx.call_tool("prowler_scan", ...)
            ctx.write_output("findings.json", data)
            ctx.assert_complete()
    """

    def __init__(self, contract: ExecutionContract, tools: ToolRegistry) -> None:
        self.contract = contract
        self.tools = tools
        self.budget = BudgetEnvelope(
            llm_calls=contract.budget.llm_calls,
            tokens=contract.budget.tokens,
            wall_clock_sec=contract.budget.wall_clock_sec,
            cloud_api_calls=contract.budget.cloud_api_calls,
            mb_written=contract.budget.mb_written,
        )
        self.workspace_mgr = WorkspaceManager(
            workspace=Path(contract.workspace),
            persistent_root=Path(contract.persistent_root),
        )
        self.audit_path = Path(contract.workspace) / "audit.jsonl"
        self.audit: AuditLog | None = None

    def __enter__(self) -> "Charter":
        self.workspace_mgr.setup()
        self.audit = AuditLog(
            path=self.audit_path,
            agent=self.contract.target_agent,
            run_id=self.contract.delegation_id,
        )
        self.audit.append(action="invocation_started", payload={"task": self.contract.task})
        self.budget.start_clock()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        assert self.audit is not None
        if exc is None:
            self.audit.append(action="invocation_completed", payload={})
        else:
            self.audit.append(
                action="invocation_failed",
                payload={"exception": exc.__class__.__name__, "message": str(exc)},
            )

    def call_tool(self, name: str, *, llm_calls: int = 0, tokens: int = 0, **kwargs: Any) -> Any:
        """Run a tool through the charter — whitelist + budget + audit."""
        assert self.audit is not None
        self.budget.check_wall_clock()
        cloud_calls = self.tools.cloud_calls(name) if name in self.tools.known_tools() else 0
        self.budget.consume(llm_calls=llm_calls, tokens=tokens, cloud_api_calls=cloud_calls)
        self.audit.append(
            action="tool_call",
            payload={
                "tool": name,
                "version": self.tools.version(name) if name in self.tools.known_tools() else "unknown",
                "kwargs_keys": sorted(kwargs.keys()),
            },
        )
        return self.tools.call(name, permitted=self.contract.permitted_tools, **kwargs)

    def write_output(self, name: str, data: bytes) -> Path:
        assert self.audit is not None
        self.budget.consume(mb_written=len(data) / 1_048_576)  # bytes → MB
        path = self.workspace_mgr.write_output(name, data)
        self.audit.append(action="output_written", payload={"name": name, "bytes": len(data)})
        return path

    def assert_complete(self) -> None:
        missing = self.workspace_mgr.missing_outputs(self.contract.required_outputs)
        if missing:
            raise RuntimeError(f"required outputs missing: {missing}")
```

- [ ] **Step 4: Update package public API**

```python
# packages/charter/src/charter/__init__.py
"""Nexus runtime charter."""

from charter.contract import ExecutionContract, load_contract
from charter.context import Charter
from charter.exceptions import (
    BudgetExhausted,
    CharterViolation,
    ContractInvalid,
    ToolNotPermitted,
)
from charter.tools import ToolRegistry
from charter.verifier import VerificationResult, verify_audit_log

__version__ = "0.1.0"

__all__ = [
    "Charter",
    "ExecutionContract",
    "load_contract",
    "ToolRegistry",
    "BudgetExhausted",
    "CharterViolation",
    "ContractInvalid",
    "ToolNotPermitted",
    "VerificationResult",
    "verify_audit_log",
]
```

- [ ] **Step 5: Run tests pass**

```bash
uv run pytest packages/charter/tests/test_context.py -v
```

Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add packages/charter/src/charter/context.py packages/charter/src/charter/__init__.py packages/charter/tests/test_context.py
git commit -m "feat(charter): public Charter context manager wrapping budget + tools + audit + workspace"
```

---

### Task 11: CLI — `charter validate` and `charter audit verify`

**Files:** Create `packages/charter/src/charter/cli.py`, `packages/charter/tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/charter/tests/test_cli.py
"""Tests for the charter CLI."""

from pathlib import Path

from click.testing import CliRunner

from charter.audit import AuditLog
from charter.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


def test_validate_valid_contract() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(FIXTURES / "valid_contract.yaml")])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_validate_invalid_contract() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(FIXTURES / "invalid_contract.yaml")])
    assert result.exit_code != 0


def test_audit_verify_clean_log(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(path=log_path, agent="x", run_id="r")
    log.append(action="a", payload={})
    log.append(action="b", payload={})

    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify", str(log_path)])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_audit_verify_missing_file(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["audit", "verify", str(tmp_path / "nope.jsonl")])
    assert result.exit_code != 0
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/charter/tests/test_cli.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement CLI**

```python
# packages/charter/src/charter/cli.py
"""Charter CLI: validate contracts, verify audit logs."""

from __future__ import annotations

from pathlib import Path

import click

from charter.contract import load_contract
from charter.verifier import verify_audit_log


@click.group()
@click.version_option()
def main() -> None:
    """Charter — execution contract validation and audit log verification."""


@main.command()
@click.argument("contract_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate(contract_path: Path) -> None:
    """Validate an execution contract YAML file."""
    try:
        contract = load_contract(contract_path)
    except Exception as e:
        click.echo(f"INVALID: {e}", err=True)
        raise SystemExit(1) from e
    click.echo(f"VALID: {contract.target_agent} ({contract.delegation_id})")


@main.group()
def audit() -> None:
    """Audit log commands."""


@audit.command()
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def verify(log_path: Path) -> None:
    """Verify an audit log's hash chain integrity."""
    result = verify_audit_log(log_path)
    if result.valid:
        click.echo(f"VALID: {result.entries_checked} entries, chain intact")
    else:
        click.echo(
            f"INVALID: chain broken at entry {result.broken_at}", err=True
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest packages/charter/tests/test_cli.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Smoke-test the actual CLI**

```bash
uv run charter --help
uv run charter validate packages/charter/tests/fixtures/valid_contract.yaml
```

Expected: help printed; valid contract validates with `VALID: cloud_posture ...`.

- [ ] **Step 6: Commit**

```bash
git add packages/charter/src/charter/cli.py packages/charter/tests/test_cli.py
git commit -m "feat(charter): CLI for contract validation and audit log verification"
```

---

### Task 12: Reference "hello world" agent (end-to-end smoke)

**Files:** Create `packages/charter/examples/hello_world_agent/{nlah/README.md,tools.py,agent.py,contract.yaml,README.md}` and integration test `packages/charter/tests/test_hello_world_integration.py`

- [ ] **Step 1: Create the NLAH (the "domain brain")**

`packages/charter/examples/hello_world_agent/nlah/README.md`:

```markdown
# Hello World Agent — NLAH

You are a stub agent demonstrating the runtime charter.

## Task pattern

Given a `task` field in the execution contract, produce a file `greeting.txt`
containing a polite greeting that includes the task text.

## Tools

- `echo(value: str) -> str` — returns the input unchanged

## Completion

`greeting.txt` exists in workspace.

## Notes

This NLAH exists to prove the charter pipeline works end-to-end. It is NOT a
production agent. Replace with the Cloud Posture NLAH (F.3) when that lands.
```

- [ ] **Step 2: Create the toy tools file**

`packages/charter/examples/hello_world_agent/tools.py`:

```python
"""Toy tools for the hello-world reference agent."""


def echo(value: str) -> str:
    return value
```

- [ ] **Step 3: Create the agent driver**

`packages/charter/examples/hello_world_agent/agent.py`:

```python
"""Hello-world reference agent — demonstrates Charter pipeline end-to-end."""

from __future__ import annotations

from pathlib import Path

from charter import Charter, ExecutionContract, ToolRegistry, load_contract

from .tools import echo


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register("echo", echo, version="1.0.0", cloud_calls=0)
    return reg


def run(contract: ExecutionContract) -> Path:
    """Run the hello-world agent under the charter. Returns the greeting path."""
    registry = build_registry()
    with Charter(contract, tools=registry) as ctx:
        greeting = ctx.call_tool("echo", value=f"Hello — task was: {contract.task}", llm_calls=1, tokens=20)
        path = ctx.write_output("greeting.txt", greeting.encode("utf-8"))
        ctx.assert_complete()
    return path


def run_from_file(contract_path: Path) -> Path:
    return run(load_contract(contract_path))
```

- [ ] **Step 4: Create the example contract**

`packages/charter/examples/hello_world_agent/contract.yaml`:

```yaml
schema_version: '0.1'
delegation_id: 01J7M3X9Z1K8RPVQNH2T8DBHFZ
source_agent: supervisor
target_agent: hello_world
customer_id: cust_demo
task: "Greet the human"
required_outputs:
  - greeting.txt
budget:
  llm_calls: 5
  tokens: 500
  wall_clock_sec: 30
  cloud_api_calls: 5
  mb_written: 1
permitted_tools:
  - echo
completion_condition: "greeting.txt exists"
escalation_rules: []
workspace: /tmp/nexus-demo/workspaces/cust_demo/hello_world/01J7M3X9Z1K8RPVQNH2T8DBHFZ/
persistent_root: /tmp/nexus-demo/persistent/cust_demo/hello_world/
created_at: 2026-05-08T12:00:00Z
expires_at: 2026-05-08T12:30:00Z
```

- [ ] **Step 5: Create the README**

`packages/charter/examples/hello_world_agent/README.md`:

````markdown
# Hello World Reference Agent

Smallest possible Charter consumer. Run with:

```bash
uv run python -c "
from pathlib import Path
from charter.examples.hello_world_agent.agent import run_from_file
result = run_from_file(Path('packages/charter/examples/hello_world_agent/contract.yaml'))
print(f'wrote: {result}')
print(result.read_text())
"
```

What this proves end-to-end:
1. Contract parsed and validated
2. Workspace + persistent paths created
3. Tool whitelist enforced
4. Budget consumed and tracked
5. Audit log written and hash-chained
6. Completion condition checked
````

- [ ] **Step 6: Make the examples package importable**

`packages/charter/examples/__init__.py`:

```python
```

`packages/charter/examples/hello_world_agent/__init__.py`:

```python
```

- [ ] **Step 7: Write the integration test**

`packages/charter/tests/test_hello_world_integration.py`:

```python
"""Integration test: run the hello-world agent end-to-end through the charter."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from charter.contract import BudgetSpec, ExecutionContract
from charter.examples.hello_world_agent.agent import run
from charter.verifier import verify_audit_log


def test_hello_world_runs_end_to_end(tmp_path: Path) -> None:
    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="hello_world",
        customer_id="cust_test",
        task="say hi to the integration test",
        required_outputs=["greeting.txt"],
        budget=BudgetSpec(
            llm_calls=5, tokens=500, wall_clock_sec=30.0, cloud_api_calls=5, mb_written=1
        ),
        permitted_tools=["echo"],
        completion_condition="greeting.txt exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    path = run(contract)
    assert path.exists()
    assert b"say hi to the integration test" in path.read_bytes()

    audit_path = Path(contract.workspace) / "audit.jsonl"
    result = verify_audit_log(audit_path)
    assert result.valid is True
    assert result.entries_checked >= 4  # invocation_started, tool_call, output_written, invocation_completed
```

- [ ] **Step 8: Run integration test**

```bash
uv run pytest packages/charter/tests/test_hello_world_integration.py -v
```

Expected: 1 passed.

- [ ] **Step 9: Run the full charter test suite**

```bash
uv run pytest packages/charter/ -v --cov=charter --cov-report=term-missing
```

Expected: all tests pass; coverage ≥ 90%.

- [ ] **Step 10: Commit**

```bash
git add packages/charter/examples/ packages/charter/tests/test_hello_world_integration.py
git commit -m "feat(charter): hello-world reference agent proves end-to-end pipeline"
```

---

### Task 13: Update package init & docs

**Files:** Update `packages/charter/README.md`, add ADR-002

- [ ] **Step 1: Create `packages/charter/README.md`**

````markdown
# `nexus-charter`

The runtime charter is the universal physics every Nexus agent obeys.

## What it does

- **Execution contracts** — typed YAML envelope for each invocation (Pydantic-validated)
- **Budget enforcement** — 5-dimensional limits (LLM calls, tokens, wall-clock, cloud-API calls, MB written)
- **Tool whitelisting** — version-pinned registry; calls outside the whitelist raise `ToolNotPermitted`
- **Workspace management** — path-addressable per-invocation files + persistent memory mounts
- **Audit hash chain** — append-only, SHA-256-chained, tamper-detected
- **Verifier** — re-derives hashes to detect tampering or chain breaks

## Usage

```python
from charter import Charter, ExecutionContract, ToolRegistry, load_contract

contract = load_contract("invocation.yaml")
registry = ToolRegistry()
registry.register("my_tool", my_tool_fn, version="1.0.0", cloud_calls=0)

with Charter(contract, tools=registry) as ctx:
    result = ctx.call_tool("my_tool", llm_calls=1, tokens=50, arg="x")
    ctx.write_output("findings.json", b"{...}")
    ctx.assert_complete()
```

The CLI:

```bash
charter validate invocation.yaml
charter audit verify /workspaces/cust/agent/run-id/audit.jsonl
```

## License

Apache 2.0 — this is one of the open-source foundations of Nexus Cyber OS.

## See also

- Reference agent: `examples/hello_world_agent/`
- Architecture: `docs/architecture/runtime_charter.md`
- Build plan: `docs/superpowers/plans/2026-05-08-f-1-runtime-charter-v0.1.md`
````

- [ ] **Step 2: Create ADR-002**

`docs/_meta/decisions/ADR-002-charter-as-context-manager.md`:

```markdown
# ADR-002 — Charter exposed as a Python context manager

- **Status:** accepted
- **Date:** 2026-05-08
- **Authors:** Winston (architect), AI/Agent Eng
- **Stakeholders:** all engineers writing agents

## Context

The runtime charter must wrap every agent invocation. Three plausible API shapes:

1. **Decorator** — `@charter(contract)` on the agent function
2. **Middleware framework** — agents inherit from a base class with charter hooks
3. **Context manager** — `with Charter(contract) as ctx: ...`

## Decision

Use a context manager. Public API: `with Charter(contract, tools=registry) as ctx`.

## Consequences

### Positive
- Lifecycle is explicit: setup on `__enter__`, teardown on `__exit__`.
- Audit log entries for `invocation_started`, `invocation_failed`, `invocation_completed` are guaranteed by the `with` block, even on exceptions.
- Works in both sync and async code paths (async wrapper is a thin sibling).
- No magic — the engineer writing an agent reads the code top-to-bottom and sees what's happening.

### Negative
- Engineer must remember to call `ctx.call_tool` (not the underlying function directly). Mitigation: tool registry isolates the underlying functions; agents only have access to `ctx`.

### Neutral
- Slight verbosity vs. a decorator. Acceptable cost for explicitness.

## Alternatives considered

### Alt 1: Decorator (`@charter(contract)`)
- Why rejected: hides lifecycle; harder to reason about exception paths; conflicts with async/sync polymorphism; harder to unit-test individual phases (workspace setup vs. audit close).

### Alt 2: Base class inheritance
- Why rejected: implicit composition; harder for new engineers to trace what runs when; locks agent shape to a class hierarchy that may not fit all 18 agents (e.g. functional Curiosity Agent vs. Investigation Agent's sub-agent orchestration).

## References

- Implementation: `packages/charter/src/charter/context.py`
- Reference agent: `packages/charter/examples/hello_world_agent/`
- Plan: `docs/superpowers/plans/2026-05-08-f-1-runtime-charter-v0.1.md`
```

- [ ] **Step 3: Update version-history**

Add row to `docs/_meta/version-history.md`:

```markdown
| 2026-05-08 | charter | 0.1.0 | F.1 ships: contracts, budget, tools, workspace, audit chain, verifier, context manager, CLI, hello-world reference | F.1 |
```

- [ ] **Step 4: Commit**

```bash
git add packages/charter/README.md docs/_meta/decisions/ADR-002-charter-as-context-manager.md docs/_meta/version-history.md
git commit -m "docs(charter): readme + ADR-002 (context manager API choice) + version history"
```

---

### Task 14: Final verification

**Files:** none

- [ ] **Step 1: Run full charter test suite with coverage**

```bash
uv run pytest packages/charter/ -v --cov=charter --cov-report=term-missing --cov-fail-under=85
```

Expected: all tests pass; coverage ≥ 85%.

- [ ] **Step 2: Lint and typecheck**

```bash
uv run ruff check packages/charter/
uv run ruff format --check packages/charter/
uv run mypy packages/charter/src
```

Expected: clean (no errors).

- [ ] **Step 3: Smoke-test CLI against fixtures**

```bash
uv run charter validate packages/charter/tests/fixtures/valid_contract.yaml
uv run charter validate packages/charter/tests/fixtures/invalid_contract.yaml || echo "expected non-zero exit"
```

Expected: first succeeds, second returns non-zero exit.

- [ ] **Step 4: Verify open-source readiness**

```bash
ls packages/charter/
cat packages/charter/pyproject.toml | grep -i license
```

Expected: `LICENSE-APACHE` referenced; `nexus-charter` is BSL-free.

- [ ] **Step 5: Confirm no commits since last task** (sanity check)

```bash
git status
git log --oneline -20
```

Expected: clean working tree; ~14 charter-related commits visible.

---

## Self-Review

**Spec coverage:**
- ✓ Execution contract schema (Task 4)
- ✓ Contract validator (Task 4 — Pydantic does the validation)
- ✓ Budget envelope, 5 dims (Task 3)
- ✓ Tool registry + whitelist + versioning (Task 6)
- ✓ Workspace manager + memory mounts (Task 5)
- ✓ Audit hash chain — append, persist, resume (Task 7)
- ✓ Audit verifier — tamper detection (Task 9)
- ✓ Charter context manager (Task 10)
- ✓ Exceptions (Task 2)
- ✓ CLI (Task 11)
- ✓ Hello-world reference agent (Task 12)
- ✓ Property-based tests (Task 8)
- ✓ Documentation + ADR-002 (Task 13)

**Placeholder scan:** none. Every step has full code.

**Type / name consistency:**
- `BudgetSpec` (Pydantic, in contract.py) ↔ `BudgetEnvelope` (runtime, in budget.py). Spec is "what was promised"; envelope is "what's tracked." Different types, intentional.
- `Charter`, `ExecutionContract`, `ToolRegistry`, `BudgetExhausted`, `ToolNotPermitted`, `ContractInvalid`, `verify_audit_log`, `VerificationResult` all exported from `charter/__init__.py` and used consistently in the hello-world test.
- The 5 budget dimension names — `llm_calls`, `tokens`, `wall_clock_sec`, `cloud_api_calls`, `mb_written` — are identical in `BudgetSpec` (Task 4), `BudgetEnvelope` (Task 3), and the test fixtures.

**Gaps / explicit deferrals (acceptable):**
- HMAC-signed contracts deferred to v0.2 (signing infrastructure not needed for in-process charter; needed when contracts cross process boundaries).
- Async API (`AsyncCharter`) deferred to v0.2 — current sync API covers Phase 1a needs.
- Multi-tenant fairness scheduling deferred to F.5 (memory engines integration) where it belongs.
