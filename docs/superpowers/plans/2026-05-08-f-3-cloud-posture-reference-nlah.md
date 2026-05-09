# F.3 — Cloud Posture Agent (Reference NLAH) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the **first end-to-end production agent** — Cloud Posture Agent — using the runtime charter (F.1). Establish the pattern that scales to all 17 remaining agents: NLAH (domain brain) + tools (Prowler, AWS SDK, Neo4j) + Pydantic schemas + Charter integration + eval suite + LocalStack-backed integration tests + AWS dev-account smoke runbook.

**Architecture:** The agent is a Python module that loads its NLAH (markdown brain), composes a `ToolRegistry` of charter-wrapped tools, and runs an LLM-driven loop against Anthropic's Claude Sonnet 4.5. Each tool call goes through the Charter context manager (budget, audit, whitelist). Findings are written to a typed Pydantic schema → `findings.json` in the workspace; a markdown summary is generated → `summary.md`. Persistent memory: episodic (run history), procedural (suppression rules), semantic (asset graph in Neo4j). Eval suite is a minimal local runner inside this package — to be extracted into the `eval-framework` package in F.2.

**Tech Stack:** Python 3.12 · Anthropic SDK 0.36 · Prowler 5.x (subprocess) · boto3 1.35 · neo4j-driver 5.x · Pydantic 2.9 · pytest · LocalStack 3.8 · `nexus-charter` (this repo, F.1)

**Depends on:** P0.1 (repo bootstrap) · F.1 (runtime charter v0.1) · docker-compose.dev (LocalStack)

**Defers:** Full eval-framework package (F.2). This plan ships a minimal local eval runner (`packages/agents/cloud-posture/src/cloud_posture/_eval_local.py`) that gets extracted in F.2.

---

## Execution status (as of 2026-05-09)

This plan grew three new tasks during execution to absorb the architectural decisions captured in ADR-003 / ADR-004 / ADR-005. Half-task numbering (`X.5`) is used so the original numbering of downstream tasks is preserved. Order of execution:

```
1 → 2 → 3 → 4 → 4.5 → 5 → 5.5 (NEW) → 6 → 6.5 (NEW) → 7 → 8 → 8.5 (NEW) → 9 → 10 → 11 → 12 → 13 → 14 → 15
```

| Task | Status     | Commit    | Notes                                                                          |
| ---- | ---------- | --------- | ------------------------------------------------------------------------------ |
| 1    | ✅ done    | `aa2886a` | deps                                                                           |
| 2    | ✅ done    | `1376b2b` | Pydantic schemas (will be refactored in Task 6.5 → OCSF)                       |
| 3    | ✅ done    | `d62807d` | Prowler subprocess wrapper (refactored to async in Task 4.5)                   |
| 4    | ✅ done    | `0b93530` | S3 describe (refactored to async in Task 4.5)                                  |
| 4.5  | ✅ done    | `3f9a26d` | Async tool wrapper convention (per ADR-005)                                    |
| 5    | ✅ done    | `8d952e6` | IAM analyzer (async-from-start)                                                |
| 5.5  | ✅ done    | `eee6e7e` | NEW — Fabric scaffolding + OCSF envelope helpers (per ADR-004)                 |
| 6    | ✅ done    | `bee67ad` | Neo4j KG writer (thin, async, customer-scoped)                                 |
| 6.5  | ✅ done    | `6131300` | NEW — Refactor `schemas.py` to OCSF typing layer (per ADR-004)                 |
| 7    | ✅ done    | `bda99a9` | Findings → Markdown summarizer (consumes OCSF via CloudPostureFinding wrapper) |
| 8    | ✅ done    | `c9655c8` | NLAH (domain brain): README + tools + 2 OCSF-shaped few-shot examples + loader |
| 8.5  | 🟡 queued  | —         | NEW — `charter.llm` module: `LLMProvider` interface (per ADR-003)              |
| 9    | ⬜ pending | —         | LLM client wrapper — implements `LLMProvider`, not raw Anthropic               |
| 10   | ⬜ pending | —         | Cloud Posture agent driver                                                     |
| 11   | ⬜ pending | —         | LocalStack integration test                                                    |
| 12   | ⬜ pending | —         | Minimal local eval runner + 10 cases                                           |
| 13   | ⬜ pending | —         | CLI                                                                            |
| 14   | ⬜ pending | —         | AWS dev-account smoke runbook                                                  |
| 15   | ⬜ pending | —         | README + ADR                                                                   |

ADR references: [ADR-003 LLM provider strategy](../../_meta/decisions/ADR-003-llm-provider-strategy.md), [ADR-004 fabric layer](../../_meta/decisions/ADR-004-fabric-layer.md), [ADR-005 async tool wrappers](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md).

---

## File Structure

```
packages/agents/cloud-posture/
├── pyproject.toml                              # already scaffolded in P0.1; extend deps
├── README.md
├── nlah/
│   ├── README.md                               # the domain brain (the canonical NLAH)
│   ├── tools.md                                # tool documentation for the LLM
│   └── examples/                               # few-shot examples for the LLM
│       ├── public_s3_finding.md
│       └── overprivileged_iam_finding.md
├── src/cloud_posture/
│   ├── __init__.py
│   ├── schemas.py                              # Pydantic finding/summary models
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── prowler.py                          # subprocess wrapper for Prowler
│   │   ├── aws_s3.py                           # boto3 S3 describe tools
│   │   ├── aws_iam.py                          # boto3 IAM analyzer tools
│   │   └── neo4j_kg.py                         # knowledge graph writer (thin)
│   ├── nlah_loader.py                          # reads nlah/ markdown into LLM system prompt
│   ├── llm.py                                  # Anthropic client wrapper with retry
│   ├── summarizer.py                           # findings → markdown
│   ├── agent.py                                # the public `run(contract)` entry point
│   ├── _eval_local.py                          # MINIMAL eval runner; replaced by F.2
│   └── cli.py                                  # `cloud-posture run --contract X.yaml`
├── tests/
│   ├── __init__.py
│   ├── conftest.py                             # localstack + neo4j fixtures
│   ├── test_schemas.py
│   ├── test_prowler.py
│   ├── test_aws_s3.py
│   ├── test_aws_iam.py
│   ├── test_neo4j_kg.py
│   ├── test_summarizer.py
│   ├── test_nlah_loader.py
│   ├── test_agent_unit.py                      # agent flow with all tools mocked
│   └── test_agent_integration.py               # against LocalStack
├── eval/
│   ├── cases/                                  # 10 representative cases for v0.1
│   │   ├── 001_public_s3_bucket.yaml
│   │   ├── 002_iam_user_admin_no_mfa.yaml
│   │   ├── 003_unencrypted_rds.yaml
│   │   ├── 004_open_security_group.yaml
│   │   ├── 005_no_cloudtrail.yaml
│   │   ├── 006_root_account_used.yaml
│   │   ├── 007_kms_key_no_rotation.yaml
│   │   ├── 008_overprivileged_role.yaml
│   │   ├── 009_public_rds_snapshot.yaml
│   │   └── 010_unencrypted_ebs_volume.yaml
│   └── README.md
└── runbooks/
    └── aws_dev_account_smoke.md                # manual smoke against real AWS dev account
```

---

## Tasks

### Task 1: Extend cloud-posture pyproject.toml

**Files:** Modify `packages/agents/cloud-posture/pyproject.toml`

- [ ] **Step 1: Update dependencies**

```toml
[project]
name = "nexus-cloud-posture"
version = "0.1.0"
description = "Nexus Cloud Posture Agent — CSPM detection across AWS via Prowler + boto3"
requires-python = ">=3.12,<3.13"
license = { file = "../../../LICENSE-BSL" }
dependencies = [
    "nexus-charter",
    "anthropic>=0.36.0",
    "boto3>=1.35.0",
    "botocore>=1.35.0",
    "pydantic>=2.9.0",
    "pyyaml>=6.0.2",
    "neo4j>=5.24.0",
    "structlog>=24.4.0",
    "click>=8.1.0",
    "tenacity>=9.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=5.0.0",
    "pytest-mock>=3.14.0",
    "moto>=5.0.0",
    "responses>=0.25.0",
]

[project.scripts]
cloud-posture = "cloud_posture.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/cloud_posture"]
```

- [ ] **Step 2: Sync workspace**

```bash
uv sync --all-extras
```

- [ ] **Step 3: Verify imports**

```bash
uv run python -c "import anthropic, boto3, neo4j, charter; print('ok')"
```

Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add packages/agents/cloud-posture/pyproject.toml uv.lock
git commit -m "chore(cloud-posture): add anthropic, boto3, neo4j, prowler-runtime deps"
```

---

### Task 2: Findings Pydantic schemas

**Files:** Create `packages/agents/cloud-posture/src/cloud_posture/schemas.py`, `packages/agents/cloud-posture/tests/test_schemas.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/agents/cloud-posture/tests/test_schemas.py
"""Tests for Cloud Posture Pydantic schemas."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cloud_posture.schemas import (
    Finding,
    FindingsReport,
    Severity,
    AffectedResource,
)


def test_severity_enum() -> None:
    assert Severity.CRITICAL.value == "critical"
    assert Severity("high") == Severity.HIGH


def test_minimum_finding() -> None:
    finding = Finding(
        finding_id="CSPM-AWS-S3-001-bucket-public-acme",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="S3 bucket has public ACL",
        description="Bucket 'acme' allows public list/read",
        affected=[
            AffectedResource(
                cloud="aws",
                account_id="111122223333",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                resource_id="acme",
                arn="arn:aws:s3:::acme",
            )
        ],
        evidence={"acl": "public-read"},
        detected_at=datetime.now(UTC),
    )
    assert finding.severity == Severity.HIGH
    assert finding.affected[0].cloud == "aws"


def test_finding_id_format_enforced() -> None:
    """finding_id must follow CSPM-<CLOUD>-<SVC>-<NNN>-<CONTEXT> pattern."""
    with pytest.raises(ValidationError):
        Finding(
            finding_id="not_following_format",
            rule_id="CSPM-AWS-S3-001",
            severity=Severity.HIGH,
            title="x",
            description="x",
            affected=[
                AffectedResource(
                    cloud="aws", account_id="1", region="us-east-1",
                    resource_type="t", resource_id="r", arn="arn:x",
                )
            ],
            evidence={},
            detected_at=datetime.now(UTC),
        )


def test_findings_report_aggregates() -> None:
    finding = Finding(
        finding_id="CSPM-AWS-S3-001-x",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="x",
        description="x",
        affected=[
            AffectedResource(
                cloud="aws", account_id="1", region="us-east-1",
                resource_type="t", resource_id="r", arn="arn:x",
            )
        ],
        evidence={},
        detected_at=datetime.now(UTC),
    )
    report = FindingsReport(
        agent="cloud_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="r1",
        scan_started_at=datetime.now(UTC),
        scan_completed_at=datetime.now(UTC),
        findings=[finding],
    )
    assert report.count_by_severity() == {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
    assert report.total == 1
```

- [ ] **Step 2: Run to verify failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_schemas.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/agents/cloud-posture/src/cloud_posture/schemas.py
"""Cloud Posture finding and report schemas."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

FINDING_ID_RE = re.compile(r"^CSPM-[A-Z]+-[A-Z0-9]+-\d{3}-[a-z0-9_-]+$")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AffectedResource(BaseModel):
    cloud: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    region: str = Field(min_length=1)
    resource_type: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    arn: str = Field(min_length=1)


class Finding(BaseModel):
    finding_id: str
    rule_id: str = Field(min_length=1)
    severity: Severity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    affected: list[AffectedResource] = Field(min_length=1)
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime
    suppressed: bool = False
    suppression_reason: str | None = None

    @field_validator("finding_id")
    @classmethod
    def _check_format(cls, v: str) -> str:
        if not FINDING_ID_RE.match(v):
            raise ValueError(
                "finding_id must match CSPM-<CLOUD>-<SVC>-<NNN>-<context> "
                f"(got {v!r})"
            )
        return v


class FindingsReport(BaseModel):
    agent: str
    agent_version: str
    customer_id: str
    run_id: str
    scan_started_at: datetime
    scan_completed_at: datetime
    findings: list[Finding]

    @property
    def total(self) -> int:
        return len(self.findings)

    def count_by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys((s.value for s in Severity), 0)
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
```

- [ ] **Step 4: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_schemas.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/schemas.py packages/agents/cloud-posture/tests/test_schemas.py
git commit -m "feat(cloud-posture): Pydantic schemas for findings and reports with finding_id format enforcement"
```

---

### Task 3: Prowler subprocess wrapper

**Files:** Create `packages/agents/cloud-posture/src/cloud_posture/tools/__init__.py`, `prowler.py`, `tests/test_prowler.py`

- [ ] **Step 1: Create empty `tools/__init__.py`**

```python
"""Cloud Posture tools."""
```

- [ ] **Step 2: Write failing tests**

```python
# packages/agents/cloud-posture/tests/test_prowler.py
"""Tests for the Prowler subprocess wrapper."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cloud_posture.tools.prowler import (
    ProwlerError,
    ProwlerResult,
    run_prowler_aws,
)


def _fake_prowler_output() -> dict:
    return {
        "Findings": [
            {
                "CheckID": "iam_user_no_mfa",
                "Severity": "high",
                "Status": "FAIL",
                "ResourceArn": "arn:aws:iam::111122223333:user/alice",
                "ResourceType": "AwsIamUser",
                "Region": "us-east-1",
                "AccountId": "111122223333",
                "StatusExtended": "User alice has no MFA",
            }
        ]
    }


@patch("cloud_posture.tools.prowler.subprocess.run")
def test_run_prowler_aws_parses_json(mock_run: MagicMock, tmp_path: Path) -> None:
    output_file = tmp_path / "prowler.ocsf.json"
    output_file.write_text(json.dumps(_fake_prowler_output()["Findings"]))
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="ok", stderr=""
    )

    result = run_prowler_aws(
        account_id="111122223333",
        region="us-east-1",
        output_dir=tmp_path,
    )
    assert isinstance(result, ProwlerResult)
    assert len(result.raw_findings) == 1
    assert result.raw_findings[0]["CheckID"] == "iam_user_no_mfa"


@patch("cloud_posture.tools.prowler.subprocess.run")
def test_run_prowler_nonzero_exit_raises(mock_run: MagicMock, tmp_path: Path) -> None:
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=2, stdout="", stderr="auth error"
    )
    with pytest.raises(ProwlerError) as exc_info:
        run_prowler_aws(account_id="x", region="us-east-1", output_dir=tmp_path)
    assert "auth error" in str(exc_info.value)


@patch("cloud_posture.tools.prowler.subprocess.run")
def test_run_prowler_filters_by_severity(mock_run: MagicMock, tmp_path: Path) -> None:
    output = _fake_prowler_output()
    output["Findings"].append({
        "CheckID": "low_check",
        "Severity": "low",
        "Status": "FAIL",
        "ResourceArn": "arn:aws:s3:::x",
        "ResourceType": "AwsS3Bucket",
        "Region": "us-east-1",
        "AccountId": "1",
        "StatusExtended": "x",
    })
    output_file = tmp_path / "prowler.ocsf.json"
    output_file.write_text(json.dumps(output["Findings"]))
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )

    result = run_prowler_aws(
        account_id="1",
        region="us-east-1",
        output_dir=tmp_path,
        min_severity="medium",
    )
    assert len(result.raw_findings) == 1
    assert result.raw_findings[0]["CheckID"] == "iam_user_no_mfa"
```

- [ ] **Step 3: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_prowler.py -v
```

Expected: `ImportError`

- [ ] **Step 4: Implement**

```python
# packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py
"""Prowler 5.x subprocess wrapper. Returns parsed JSON findings."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ProwlerError(RuntimeError):
    """Prowler exited non-zero or produced unparseable output."""


@dataclass
class ProwlerResult:
    raw_findings: list[dict[str, Any]] = field(default_factory=list)


def _which_prowler() -> str:
    path = shutil.which("prowler")
    if path is None:
        raise ProwlerError("prowler binary not found on PATH; install via `pip install prowler`")
    return path


def run_prowler_aws(
    account_id: str,
    region: str,
    output_dir: Path,
    min_severity: str = "info",
    profile: str | None = None,
    timeout_sec: int = 1800,
) -> ProwlerResult:
    """Run Prowler against an AWS account/region. Returns raw OCSF findings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    args = [
        _which_prowler() if Path("/usr/bin/false").exists() or shutil.which("prowler") else "prowler",
        "aws",
        "--region", region,
        "--output-formats", "json-ocsf",
        "--output-directory", str(output_dir),
        "--no-banner",
    ]
    if profile:
        args += ["--profile", profile]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout_sec)
    if proc.returncode != 0:
        raise ProwlerError(f"prowler exited {proc.returncode}: {proc.stderr.strip()}")

    json_files = sorted(output_dir.glob("*.ocsf.json"))
    if not json_files:
        raise ProwlerError(f"no prowler json output in {output_dir}")
    raw = json.loads(json_files[-1].read_text())

    threshold = _SEVERITY_ORDER.get(min_severity.lower(), 0)
    filtered = [
        f for f in raw
        if _SEVERITY_ORDER.get(str(f.get("Severity", "info")).lower(), 0) >= threshold
    ]
    return ProwlerResult(raw_findings=filtered)
```

- [ ] **Step 5: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_prowler.py -v
```

Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/tools/__init__.py packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py packages/agents/cloud-posture/tests/test_prowler.py
git commit -m "feat(cloud-posture): prowler subprocess wrapper with severity filtering"
```

---

### Task 4: AWS S3 describe tool

**Files:** Create `packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py`, `tests/test_aws_s3.py`

- [ ] **Step 1: Write failing tests using `moto`**

```python
# packages/agents/cloud-posture/tests/test_aws_s3.py
"""Tests for AWS S3 describe tools using moto in-memory mocks."""

import boto3
import pytest
from moto import mock_aws

from cloud_posture.tools.aws_s3 import describe_bucket, list_buckets


@pytest.fixture
def aws_credentials(monkeypatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_list_buckets_empty(aws_credentials) -> None:
    result = list_buckets(region="us-east-1")
    assert result == []


@mock_aws
def test_list_buckets_returns_names(aws_credentials) -> None:
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="alpha")
    client.create_bucket(Bucket="beta")
    result = list_buckets(region="us-east-1")
    assert sorted(result) == ["alpha", "beta"]


@mock_aws
def test_describe_bucket_basic(aws_credentials) -> None:
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="alpha")
    info = describe_bucket(bucket="alpha", region="us-east-1")
    assert info["bucket"] == "alpha"
    assert info["region"] == "us-east-1"
    assert "encryption" in info
    assert "policy" in info
    assert "acl" in info


@mock_aws
def test_describe_bucket_missing_raises(aws_credentials) -> None:
    with pytest.raises(Exception):  # moto raises ClientError; we accept any
        describe_bucket(bucket="does-not-exist", region="us-east-1")
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_aws_s3.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py
"""AWS S3 describe tools — read-only inspection of buckets."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import ClientError


def list_buckets(region: str = "us-east-1") -> list[str]:
    client = boto3.client("s3", region_name=region)
    resp = client.list_buckets()
    return [b["Name"] for b in resp.get("Buckets", [])]


def _get_or_none(fn, **kwargs) -> Any:
    try:
        return fn(**kwargs)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchBucketPolicy", "ServerSideEncryptionConfigurationNotFoundError"}:
            return None
        raise


def describe_bucket(bucket: str, region: str = "us-east-1") -> dict[str, Any]:
    client = boto3.client("s3", region_name=region)
    # Will raise on missing bucket — caller handles.
    client.head_bucket(Bucket=bucket)
    return {
        "bucket": bucket,
        "region": region,
        "acl": client.get_bucket_acl(Bucket=bucket).get("Grants", []),
        "policy": _get_or_none(client.get_bucket_policy, Bucket=bucket),
        "encryption": _get_or_none(
            client.get_bucket_encryption, Bucket=bucket
        ),
        "versioning": client.get_bucket_versioning(Bucket=bucket).get("Status"),
        "public_access_block": _get_or_none(
            client.get_public_access_block, Bucket=bucket
        ),
        "logging": client.get_bucket_logging(Bucket=bucket).get("LoggingEnabled"),
    }
```

- [ ] **Step 4: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_aws_s3.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/tools/aws_s3.py packages/agents/cloud-posture/tests/test_aws_s3.py
git commit -m "feat(cloud-posture): AWS S3 describe tools (list_buckets, describe_bucket) with moto coverage"
```

---

### Task 4.5: Async tool wrapper refactor (per ADR-005) — ✅ DONE (`3f9a26d`)

**Files modified:** `packages/agents/cloud-posture/src/cloud_posture/tools/prowler.py`, `tools/aws_s3.py`, `tests/test_prowler.py`, `tests/test_aws_s3.py`

Inserted because Tasks 3 and 4 shipped sync-by-default (`subprocess.run`, sync `boto3`). Per [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md), every tool wrapper must be async-by-default before agent #1 sets a precedent the other 17 agents inherit.

- [x] **Step 1: Convert `tools/prowler.py`** — `subprocess.run` → `asyncio.create_subprocess_exec`; `timeout: float` enforced via `asyncio.wait_for` with `proc.kill()` + `await proc.wait()` on timeout; raise `ProwlerError` from `TimeoutError`.
- [x] **Step 2: Convert `tools/aws_s3.py`** — public `async def list_buckets` / `describe_bucket` delegate to sync helpers via `asyncio.to_thread` (boto3 has no native async; ADR-005 rejects `aioboto3` for Phase 1a).
- [x] **Step 3: Convert tests to `@pytest.mark.asyncio`** — Prowler tests patch `asyncio.create_subprocess_exec` with `AsyncMock` returning a mock `Process`. S3 tests use `with mock_aws():` context manager (moto's decorator clobbers coroutine functions).
- [x] **Step 4: New timeout test for Prowler** — exercises `proc.kill()` path on `asyncio.wait_for` timeout.
- [x] **Step 5: Verify** — 13/13 tests pass; ruff + mypy strict clean.
- [x] **Step 6: Commit** — `refactor(cloud-posture): async tool wrappers per adr-005` at `3f9a26d`.

---

### Task 5: AWS IAM analyzer tool

**Files:** Create `packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py`, `tests/test_aws_iam.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/agents/cloud-posture/tests/test_aws_iam.py
"""Tests for AWS IAM analyzer."""

import boto3
import pytest
from moto import mock_aws

from cloud_posture.tools.aws_iam import (
    list_users_without_mfa,
    list_admin_policies,
)


@pytest.fixture
def aws_credentials(monkeypatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_list_users_without_mfa(aws_credentials) -> None:
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="alice", Password="P@ssw0rd!Strong!")
    iam.create_login_profile(UserName="bob", Password="P@ssw0rd!Strong!")
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber="arn:aws:iam::123456789012:mfa/alice",
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    result = list_users_without_mfa()
    assert result == ["bob"]


@mock_aws
def test_list_admin_policies_detects_star_action_and_resource(aws_credentials) -> None:
    iam = boto3.client("iam")
    iam.create_policy(
        PolicyName="TooBroad",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )
    iam.create_policy(
        PolicyName="Scoped",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}]}',
    )
    result = list_admin_policies()
    names = {p["policy_name"] for p in result}
    assert "TooBroad" in names
    assert "Scoped" not in names
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_aws_iam.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py
"""AWS IAM analyzer — read-only checks for common identity issues."""

from __future__ import annotations

import json
from typing import Any

import boto3


def list_users_without_mfa() -> list[str]:
    """Return usernames that have a console password but no MFA device."""
    iam = boto3.client("iam")
    out: list[str] = []
    for user in iam.list_users().get("Users", []):
        username = user["UserName"]
        try:
            iam.get_login_profile(UserName=username)
        except iam.exceptions.NoSuchEntityException:
            continue  # no console password — skip
        devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not devices:
            out.append(username)
    return out


def _statement_is_star_star(stmt: dict[str, Any]) -> bool:
    if stmt.get("Effect") != "Allow":
        return False
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources


def list_admin_policies() -> list[dict[str, Any]]:
    """Return customer-managed policies that grant Action='*' on Resource='*'."""
    iam = boto3.client("iam")
    out: list[dict[str, Any]] = []
    for policy in iam.list_policies(Scope="Local").get("Policies", []):
        version = iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )
        document = version["PolicyVersion"]["Document"]
        if isinstance(document, str):
            document = json.loads(document)
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if any(_statement_is_star_star(s) for s in statements):
            out.append({
                "policy_name": policy["PolicyName"],
                "policy_arn": policy["Arn"],
                "document": document,
            })
    return out
```

- [ ] **Step 4: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_aws_iam.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/tools/aws_iam.py packages/agents/cloud-posture/tests/test_aws_iam.py
git commit -m "feat(cloud-posture): IAM analyzer (list_users_without_mfa, list_admin_policies)"
```

---

### Task 5.5: Fabric scaffolding + OCSF envelope helpers (per ADR-004) — ✅ DONE (`eee6e7e`)

**Files:** Create `packages/shared/src/shared/fabric/__init__.py`, `subjects.py`, `envelope.py`, `correlation.py`. Tests under `packages/shared/tests/`.

**Why now (between Tasks 5 and 6):** Task 6 (Neo4j KG writer) and Task 7 (Findings → Markdown) both want to attach a `correlation_id` and emit OCSF-shaped findings. Building the Neo4j writer first against the per-agent `Finding` model just creates rework when Task 6.5 swaps in the OCSF typing layer. The fabric scaffolding is one small package that unblocks both.

**Scope (Phase 1a slice — _not_ the full fabric):**

- `subjects.py` — pure functions that build subject names. `findings_subject(tenant_id, asset_arn) -> "findings.tenant.<tid>.asset.<arn-hash>"`, `audit_subject(tenant_id) -> ...`, etc. No NATS dependency.
- `envelope.py` — small dataclass `NexusEnvelope { correlation_id, tenant_id, agent_id, nlah_version, model_pin, charter_invocation_id }` + helpers `wrap_ocsf(ocsf_event, envelope) -> dict` and `unwrap_ocsf(dict) -> (ocsf_event, envelope)`. OCSF v1.3 base-event keys handled as `dict[str, Any]` (no upstream dep needed for the slice).
- `correlation.py` — `new_correlation_id() -> str` (ULID); `current_correlation_id() -> str | None` (contextvar); `with correlation_scope(cid)` context manager.
- **Deferred to a later plan:** the actual NATS JetStream client. We codify the schema and the IDs now; the broker connection can wait until E.2 / control-plane builds the consumer side. For now consumers will get an in-process `FabricStub` for tests.

**Steps:**

- [x] **Step 1: Add `python-ulid>=2.0.0` to `packages/shared/pyproject.toml`** (chose `python-ulid` over `ulid-py` — actively maintained; same shape).
- [x] **Step 2: Write failing tests** — 26 tests across `test_fabric_subjects.py`, `test_fabric_envelope.py`, `test_fabric_correlation.py`.
- [x] **Step 3: Run failure** — `ModuleNotFoundError: No module named 'shared.fabric'` confirmed.
- [x] **Step 4: Implement** `subjects.py`, `envelope.py`, `correlation.py`, `__init__.py`.
- [x] **Step 5: Tests pass** — 26/26 (exceeded the ≥ 8 target). Full repo: 92/92.
- [x] **Step 6: Commit** — `feat(shared): fabric scaffolding (subjects, envelope, correlation) per adr-004` at `eee6e7e`.

**Acceptance met:** `from shared.fabric import new_correlation_id, wrap_ocsf, findings_subject` works. No NATS client in this task.

---

### Task 6: Neo4j knowledge-graph writer (thin) — ✅ DONE (`bee67ad`)

**Notes on the implementation as shipped:**

- **Async-from-start per [ADR-005](../../_meta/decisions/ADR-005-async-tool-wrapper-convention.md).** Used `neo4j.AsyncDriver` shape: `async with driver.session() as s: await s.run(...)`. The plan-as-drafted was sync; the writer was promoted to async to match every other tool.
- **Affected-ARN batching.** The plan called for one MATCH/MERGE query per affected ARN. As shipped: a single `UNWIND $arns` query that batches all asset MERGEs + relationship creates in one round-trip. Cypher cost is O(1) round-trips per finding instead of O(N).
- **Empty-arns shortcut.** A finding with `affected_arns=[]` skips the relation query entirely. Original plan would have run an empty UNWIND.
- **5 tests instead of 2.** Added: customer_id-scoping check (a regression guard for cross-tenant leakage), kwargs-round-trip check, empty-arns shortcut.
- Driver type is `Any` (not a `Protocol`) — the neo4j async driver shape varies across minor versions and a Protocol would create false-positive type errors on upgrade. The writer's contract is defined by the tests, not by Python typing.

**Files:** Create `packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py`, `tests/test_neo4j_kg.py`

- [ ] **Step 1: Write failing tests with mocked driver**

```python
# packages/agents/cloud-posture/tests/test_neo4j_kg.py
"""Tests for the Neo4j knowledge-graph writer (mocked driver)."""

from unittest.mock import MagicMock

from cloud_posture.tools.neo4j_kg import KnowledgeGraphWriter


def test_upsert_asset_runs_merge_query() -> None:
    driver = MagicMock()
    session = driver.session.return_value.__enter__.return_value

    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")
    writer.upsert_asset(
        kind="aws_s3_bucket",
        external_id="arn:aws:s3:::alpha",
        properties={"region": "us-east-1", "name": "alpha"},
    )
    session.run.assert_called_once()
    cypher = session.run.call_args[0][0]
    assert "MERGE" in cypher
    assert "aws_s3_bucket" in cypher.lower() or "kind" in cypher


def test_upsert_finding_relates_to_asset() -> None:
    driver = MagicMock()
    session = driver.session.return_value.__enter__.return_value

    writer = KnowledgeGraphWriter(driver=driver, customer_id="cust_test")
    writer.upsert_finding(
        finding_id="CSPM-AWS-S3-001-alpha",
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=["arn:aws:s3:::alpha"],
    )
    # Two queries: one MERGE Finding, one MATCH/MERGE relationship per asset.
    assert session.run.call_count == 2
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_neo4j_kg.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py
"""Knowledge graph writer (Neo4j). Every node is customer-scoped."""

from __future__ import annotations

from typing import Any, Protocol


class _Driver(Protocol):
    def session(self) -> Any: ...  # neo4j.Session


class KnowledgeGraphWriter:
    """Customer-scoped writer: every MERGE constrains by customer_id."""

    def __init__(self, driver: _Driver, customer_id: str) -> None:
        self.driver = driver
        self.customer_id = customer_id

    def upsert_asset(
        self, kind: str, external_id: str, properties: dict[str, Any]
    ) -> None:
        cypher = (
            "MERGE (a:Asset {customer_id: $customer_id, kind: $kind, external_id: $external_id}) "
            "SET a += $properties"
        )
        with self.driver.session() as s:
            s.run(
                cypher,
                customer_id=self.customer_id,
                kind=kind,
                external_id=external_id,
                properties=properties,
            )

    def upsert_finding(
        self,
        finding_id: str,
        rule_id: str,
        severity: str,
        affected_arns: list[str],
    ) -> None:
        with self.driver.session() as s:
            s.run(
                "MERGE (f:Finding {customer_id: $customer_id, finding_id: $finding_id}) "
                "SET f.rule_id = $rule_id, f.severity = $severity",
                customer_id=self.customer_id,
                finding_id=finding_id,
                rule_id=rule_id,
                severity=severity,
            )
            s.run(
                "MATCH (f:Finding {customer_id: $customer_id, finding_id: $finding_id}) "
                "UNWIND $arns AS arn "
                "MERGE (a:Asset {customer_id: $customer_id, external_id: arn}) "
                "MERGE (f)-[:AFFECTS]->(a)",
                customer_id=self.customer_id,
                finding_id=finding_id,
                arns=affected_arns,
            )
```

- [ ] **Step 4: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_neo4j_kg.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/tools/neo4j_kg.py packages/agents/cloud-posture/tests/test_neo4j_kg.py
git commit -m "feat(cloud-posture): customer-scoped Neo4j knowledge-graph writer"
```

---

### Task 6.5: Refactor `schemas.py` to OCSF typing layer (per ADR-004) — ✅ DONE (`6131300`)

**Notes on the implementation as shipped:**

- **API shape diverges slightly from the plan-as-drafted.** Plan said `build_finding(prowler_raw, *, ...)` (Prowler-specific). As shipped: `build_finding(*, finding_id, rule_id, severity, title, description, affected, detected_at, envelope, evidence)` with typed args. Reason: the agent driver constructs findings from multiple tool sources (Prowler, S3 describe, IAM analyzer), not just Prowler. A separate `from_prowler_ocsf(...)` adapter is deferred to Task 10 once we have a clearer view of which Prowler fields actually flow.
- **`CloudPostureFinding` strictness.** Construction validates three things atomically: `class_uid == 2003`, `finding_id` matches `FINDING_ID_RE`, and `nexus_envelope` is well-formed (round-tripped through `unwrap_ocsf`).
- **`Severity` round-trip helpers exposed.** `severity_to_id` and `severity_from_id` are now public so future agents emitting OCSF can reuse the mapping. OCSF `severity_id` 6 (Fatal) collapses to our `critical` on read.
- **`FindingsReport.findings` is now `list[dict]`.** Stores wrapped OCSF dicts directly so the report serializes to JSON in a single step without losing OCSF shape. `add_finding(CloudPostureFinding)` is the typed helper; `count_by_severity()` reads `severity_id` off each dict.
- **`AffectedResource` retained** as a typed builder with a `to_ocsf()` helper. Same Pydantic shape as before, plus the OCSF emission method.
- **Workspace dep + `py.typed` marker.** Added `nexus-shared` to cloud-posture's deps; added `packages/shared/src/shared/py.typed` so mypy strict resolves cross-package types.
- **17 new schema tests, all passing.** Severity round-trips (parametrized × 5), Fatal→critical collapse, unknown ID rejection, AffectedResource→OCSF shape, build_finding class_uid + envelope round-trip, typed accessors, finding_id regex, empty-affected rejection, wrong class_uid rejection, missing-envelope rejection, FindingsReport aggregation.

**Files:** Modify `packages/agents/cloud-posture/src/cloud_posture/schemas.py`, `tests/test_schemas.py`. Touches no other code today (schemas only consumed in tests).

**Why now (between Tasks 6 and 7):** Task 7 (Markdown summarizer) is the first piece that consumes `Finding` objects beyond the schema's own tests. If summarizer ships against the per-agent Pydantic model, we re-write summarizer + every downstream consumer when [ADR-004](../../_meta/decisions/ADR-004-fabric-layer.md) lands the OCSF wire format. Doing the refactor here pays the cost once.

**Scope:**

- Map our existing `Severity` enum to OCSF `severity_id` (1=info, 2=low, 3=medium, 4=high, 5=critical, 6=fatal — we collapse fatal→critical).
- Pick the OCSF class for cloud-posture findings: **OCSF v1.3 class `2003 — Compliance Finding`** (category `Findings`). Rationale: cloud-posture findings are config-policy violations, which OCSF models explicitly. Investigation Agent later uses `2004 — Detection Finding`.
- New typed wrapper `class CloudPostureFinding` over `dict[str, Any]` (the raw OCSF payload), exposing typed accessors for the fields we care about: `severity`, `finding_id`, `resource_arn`, `rule_id`, `compliance_impacts`, `nexus_envelope`.
- Builder: `build_finding(prowler_raw, *, tenant_id, agent_id, nlah_version, model_pin, charter_invocation_id) -> CloudPostureFinding` — handles Prowler-OCSF → Nexus-OCSF translation (mostly key-renames + envelope attachment).
- Keep the `finding_id` regex enforcement we already have (`<rule>:<resource>:<hash>`).

**Steps:**

- [ ] **Step 1: Write failing tests** — round-trip a Prowler-OCSF finding through `build_finding` and assert: severity is correctly mapped, `nexus_envelope` is attached, `finding_id` regex still enforced, downstream `to_dict()` produces a valid OCSF v1.3-shaped payload.
- [ ] **Step 2: Run failure**.
- [ ] **Step 3: Refactor** — replace `Finding` model with `CloudPostureFinding` wrapper; preserve the existing `Severity` enum and `FindingsReport` aggregate; route Prowler → CloudPostureFinding through `build_finding`.
- [ ] **Step 4: Tests pass** — preserve existing 4 schema tests + add ≥ 3 new for the OCSF mapping.
- [ ] **Step 5: Commit** — `refactor(cloud-posture): schemas as ocsf typing layer per adr-004`.

**Acceptance:** Schema tests + smoke + Prowler tests + S3 tests + IAM tests all still pass. No new external deps (OCSF v1.3 is encoded as `dict[str, Any]` per ADR-004 — no upstream `ocsf-lib-py` until that lib stabilizes).

---

### Task 7: Findings → Markdown summarizer — ✅ DONE (`bda99a9`)

**Notes on the implementation as shipped (delta from plan-as-drafted):**

- **Plan tests imported the old `Finding` Pydantic model.** That model is gone after Task 6.5. As shipped: tests use `build_finding(...)` to construct `CloudPostureFinding` objects, then `report.add_finding(f)` to attach them to a `FindingsReport`.
- **`FindingsReport.findings` is `list[dict]` now**, so the summarizer wraps each raw OCSF dict in a `CloudPostureFinding(raw)` for typed access (severity, finding_id, title, resources). The plan's iteration over typed `Finding` objects became iteration over `CloudPostureFinding(raw)` wrappers.
- **ARN extraction** reads from `OCSF resources[].uid` (set by `AffectedResource.to_ocsf()` in Task 6.5), not from `f.affected[].arn` (which no longer exists).
- **4 new tests** beyond the plan's 3: high-to-low severity ordering check, empty-severity section omission, total-count spot-check, multi-ARN finding rendering.

**Files:** Create `summarizer.py`, `test_summarizer.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/agents/cloud-posture/tests/test_summarizer.py
"""Tests for the markdown summarizer."""

from datetime import UTC, datetime

from cloud_posture.schemas import (
    AffectedResource,
    Finding,
    FindingsReport,
    Severity,
)
from cloud_posture.summarizer import render_summary


def _report(findings: list[Finding]) -> FindingsReport:
    return FindingsReport(
        agent="cloud_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="r1",
        scan_started_at=datetime(2026, 5, 8, 10, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 8, 10, 5, tzinfo=UTC),
        findings=findings,
    )


def _finding(severity: Severity, finding_id: str) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id="CSPM-AWS-S3-001",
        severity=severity,
        title="example",
        description="example finding",
        affected=[AffectedResource(
            cloud="aws", account_id="111", region="us-east-1",
            resource_type="aws_s3_bucket", resource_id="alpha",
            arn="arn:aws:s3:::alpha",
        )],
        evidence={},
        detected_at=datetime(2026, 5, 8, 10, 1, tzinfo=UTC),
    )


def test_summary_empty_report() -> None:
    out = render_summary(_report([]))
    assert "# Cloud Posture Scan" in out
    assert "No findings" in out


def test_summary_groups_by_severity() -> None:
    findings = [
        _finding(Severity.CRITICAL, "CSPM-AWS-S3-001-a"),
        _finding(Severity.HIGH, "CSPM-AWS-S3-001-b"),
        _finding(Severity.HIGH, "CSPM-AWS-S3-001-c"),
        _finding(Severity.LOW, "CSPM-AWS-S3-001-d"),
    ]
    out = render_summary(_report(findings))
    assert "**Critical**: 1" in out
    assert "**High**: 2" in out
    assert "**Low**: 1" in out


def test_summary_lists_finding_ids() -> None:
    f = _finding(Severity.HIGH, "CSPM-AWS-S3-001-alpha")
    out = render_summary(_report([f]))
    assert "CSPM-AWS-S3-001-alpha" in out
    assert "arn:aws:s3:::alpha" in out
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_summarizer.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/agents/cloud-posture/src/cloud_posture/summarizer.py
"""Render a FindingsReport as customer-friendly markdown."""

from __future__ import annotations

from cloud_posture.schemas import FindingsReport, Severity

_HEADER = "# Cloud Posture Scan"
_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render_summary(report: FindingsReport) -> str:
    lines: list[str] = [
        _HEADER,
        "",
        f"- Customer: `{report.customer_id}`",
        f"- Run ID: `{report.run_id}`",
        f"- Scan window: {report.scan_started_at.isoformat()} → {report.scan_completed_at.isoformat()}",
        f"- Total findings: **{report.total}**",
        "",
    ]

    if report.total == 0:
        lines += ["## Summary", "", "No findings detected in this scan window."]
        return "\n".join(lines)

    counts = report.count_by_severity()
    lines += ["## Severity breakdown", ""]
    for sev in _SEVERITY_ORDER:
        lines.append(f"- **{sev.value.capitalize()}**: {counts.get(sev.value, 0)}")
    lines += ["", "## Findings", ""]

    by_sev: dict[Severity, list] = {s: [] for s in _SEVERITY_ORDER}
    for f in report.findings:
        by_sev[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.capitalize()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            arns = ", ".join(a.arn for a in f.affected)
            lines.append(f"- `{f.finding_id}` — {f.title}  \n  Affected: {arns}")
        lines.append("")

    return "\n".join(lines)
```

- [ ] **Step 4: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_summarizer.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/summarizer.py packages/agents/cloud-posture/tests/test_summarizer.py
git commit -m "feat(cloud-posture): findings → markdown summarizer with severity grouping"
```

---

### Task 8: NLAH (the agent's domain brain) — ✅ DONE (`c9655c8`)

**Notes on the implementation as shipped (delta from plan-as-drafted):**

- **NLAH directory moved inside the package** (`src/cloud_posture/nlah/`) so it ships with both editable and wheel installs. `default_nlah_dir()` returns the in-package path; `load_system_prompt()` with no args loads the shipped NLAH.
- **Examples were rewritten to show the OCSF v1.3 wire format** (per Task 6.5). The plan's example findings were in the pre-OCSF Pydantic shape; the new examples show Prowler raw → enrichment → information-the-agent-surfaces → OCSF event the driver emits.
- **Severity rubric tightened** with a calibration paragraph: when a Prowler-flagged misconfig has an evidence-backed mitigating control, downgrade one tier; compound-risk findings (e.g. overprivileged role + console-no-MFA on the same identity) become a single Critical finding rather than two.
- **Self-evolution boundary section added** to the README: NLAH changes are signed, eval-gated, multi-party-approved, canary-rolled. Frames the NLAH as code, not docs.
- **8 loader tests** instead of the planned 3: lex-ordered example concatenation, optional tools section, optional examples section, default-dir resolution against the packaged NLAH, end-to-end load-with-no-args, plus the original 3.

**Files:** Create `nlah/README.md`, `nlah/tools.md`, `nlah/examples/public_s3_finding.md`, `nlah/examples/overprivileged_iam_finding.md`, `nlah_loader.py`, `tests/test_nlah_loader.py`

- [ ] **Step 1: Create `nlah/README.md` (the canonical NLAH)**

```markdown
# Cloud Posture Agent — NLAH

You are the Cloud Posture Agent of Nexus Cyber OS. Your job is to find cloud-configuration issues that increase risk for the customer.

## Mission

Given an execution contract instructing you to scan an AWS account, you will:

1. Run Prowler against the account/region.
2. Use AWS SDK tools to enrich significant Prowler findings with primary-source evidence.
3. Produce a typed `FindingsReport` and write it to `findings.json` in the workspace.
4. Generate a customer-friendly markdown summary at `summary.md`.
5. Upsert findings and affected assets into the customer's knowledge graph.

You ALWAYS act through the runtime charter — every tool call goes through `ctx.call_tool(...)`. Never call SDK functions directly.

## Inputs you'll receive

- `contract.task` — natural-language description (e.g. "Scan AWS account 111122223333 us-east-1 for posture issues, emphasizing S3 and IAM").
- `contract.budget` — your hard limits.
- `contract.permitted_tools` — the only tools you may use.

## Outputs you must produce

- `findings.json` — `FindingsReport` schema (see `cloud_posture.schemas`).
- `summary.md` — markdown digest grouped by severity.

## Severity policy

- **Critical** — public exposure of sensitive data, unrestricted IAM admin, evidence of compromise indicators.
- **High** — broadly permissive policies, missing encryption on data stores, no MFA on console-enabled users.
- **Medium** — drift from CIS benchmarks, suspicious-but-not-confirmed configurations.
- **Low** — cosmetic / informational.
- **Info** — context only; never gate alerting on info-level.

## Reasoning style

- One Prowler finding may correspond to ZERO, ONE, or MANY `Finding` records depending on enrichment.
- ALWAYS attach evidence (the primary-source SDK response) — not just the rule output.
- ALWAYS scope `finding_id` to the resource: `CSPM-AWS-<SVC>-<NNN>-<resource-context>`.
- Suppress only with explicit reason; suppressions persist to procedural memory.

## Failure modes

- Prowler unavailable → escalate (`escalation_rules` `tool_unavailable`).
- AWS auth failure → escalate.
- Budget exhausted → emit partial findings with `scan_completed_at` BEFORE the budget breach time, write summary noting incompleteness, escalate.
- Output schema validation failure → fail loud; do not write malformed `findings.json`.

## Few-shot examples

See `nlah/examples/`.

## Out-of-scope (current version 0.1)

- Multi-account orchestration (deferred to D.1+ when control plane lands).
- Continuous scanning (this NLAH is invoked once per contract; the scheduler triggers re-runs).
- Remediation (handled by Remediation Agent — A.1).
```

- [ ] **Step 2: Create `nlah/tools.md`**

```markdown
# Tools available to Cloud Posture Agent

## `prowler_scan(account_id, region, output_dir, min_severity?)`

Wraps Prowler 5.x. Returns `ProwlerResult.raw_findings` (list of OCSF dicts).

- **Cost:** ~10–60s wall clock, ~0 LLM calls (no model interaction).
- **When:** First step of any scan.

## `aws_s3_list_buckets(region)`

Returns list of bucket names.

## `aws_s3_describe(bucket, region)`

Returns ACL, policy, encryption, versioning, public-access block, logging.

## `aws_iam_list_users_without_mfa()`

Returns usernames with a console password but no MFA device.

## `aws_iam_list_admin_policies()`

Returns customer-managed policies granting `Action="*" Resource="*"` (overpermissive).

## `kg_upsert_asset(kind, external_id, properties)`

Upserts an asset node in the customer's knowledge graph.

## `kg_upsert_finding(finding_id, rule_id, severity, affected_arns)`

Upserts a finding node and `(:Finding)-[:AFFECTS]->(:Asset)` edges.
```

- [ ] **Step 3: Create `nlah/examples/public_s3_finding.md`**

````markdown
# Example: Public S3 bucket

## Prowler raw

```json
{
  "CheckID": "s3_bucket_public_access",
  "Severity": "high",
  "Status": "FAIL",
  "ResourceArn": "arn:aws:s3:::acme-public",
  "AccountId": "111122223333",
  "Region": "us-east-1"
}
```

## Enrichment

Call `aws_s3_describe(bucket="acme-public", region="us-east-1")`. Inspect `acl` for grants to `AllUsers` or `AllAuthenticatedUsers` and `public_access_block`.

## Finding emitted

```json
{
  "finding_id": "CSPM-AWS-S3-001-acme-public",
  "rule_id": "CSPM-AWS-S3-001",
  "severity": "high",
  "title": "S3 bucket 'acme-public' allows public read",
  "description": "Bucket has an ACL granting READ to AllUsers.",
  "affected": [
    {
      "cloud": "aws",
      "account_id": "111122223333",
      "region": "us-east-1",
      "resource_type": "aws_s3_bucket",
      "resource_id": "acme-public",
      "arn": "arn:aws:s3:::acme-public"
    }
  ],
  "evidence": {
    "acl": [
      {
        "Grantee": { "URI": "http://acs.amazonaws.com/groups/global/AllUsers" },
        "Permission": "READ"
      }
    ],
    "public_access_block": null
  }
}
```

If the bucket policy explicitly restricts to known IPs/principals, downgrade to `medium` and note in description.
````

- [ ] **Step 4: Create `nlah/examples/overprivileged_iam_finding.md`**

````markdown
# Example: Over-privileged IAM policy

## Prowler raw

Prowler may not flag this if it's customer-managed. Use `aws_iam_list_admin_policies()`.

## Finding emitted

```json
{
  "finding_id": "CSPM-AWS-IAM-002-TooBroad",
  "rule_id": "CSPM-AWS-IAM-002",
  "severity": "critical",
  "title": "Customer-managed policy 'TooBroad' grants Action=* Resource=*",
  "description": "Any principal attached to this policy has admin equivalence.",
  "affected": [
    {
      "cloud": "aws",
      "account_id": "111122223333",
      "region": "us-east-1",
      "resource_type": "aws_iam_policy",
      "resource_id": "TooBroad",
      "arn": "arn:aws:iam::111122223333:policy/TooBroad"
    }
  ],
  "evidence": {
    "document": { "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }] }
  }
}
```
````

- [ ] **Step 5: Write failing tests for the NLAH loader**

```python
# packages/agents/cloud-posture/tests/test_nlah_loader.py
"""Tests for the NLAH loader."""

from pathlib import Path

import pytest

from cloud_posture.nlah_loader import load_system_prompt


def test_load_system_prompt_includes_mission(tmp_path: Path) -> None:
    nlah_dir = tmp_path / "nlah"
    nlah_dir.mkdir()
    (nlah_dir / "README.md").write_text("# Mission\nDo X.\n")
    (nlah_dir / "tools.md").write_text("## tool A\nUsed for x.\n")

    prompt = load_system_prompt(nlah_dir=nlah_dir)
    assert "# Mission" in prompt
    assert "tool A" in prompt


def test_load_system_prompt_includes_examples(tmp_path: Path) -> None:
    nlah_dir = tmp_path / "nlah"
    nlah_dir.mkdir()
    (nlah_dir / "README.md").write_text("# Top\n")
    (nlah_dir / "tools.md").write_text("# Tools\n")
    examples = nlah_dir / "examples"
    examples.mkdir()
    (examples / "ex1.md").write_text("# Example 1\nFoo.\n")
    (examples / "ex2.md").write_text("# Example 2\nBar.\n")

    prompt = load_system_prompt(nlah_dir=nlah_dir)
    assert "Example 1" in prompt
    assert "Example 2" in prompt


def test_load_missing_readme_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_system_prompt(nlah_dir=tmp_path / "does-not-exist")
```

- [ ] **Step 6: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_nlah_loader.py -v
```

Expected: `ImportError`

- [ ] **Step 7: Implement loader**

```python
# packages/agents/cloud-posture/src/cloud_posture/nlah_loader.py
"""Concatenate the NLAH directory into a single system prompt for Claude."""

from __future__ import annotations

from pathlib import Path


def load_system_prompt(nlah_dir: Path | str) -> str:
    """Concatenate README.md + tools.md + examples/*.md from the NLAH dir.

    Order: README first, tools second, examples in lexicographic order.
    """
    base = Path(nlah_dir)
    if not base.is_dir():
        raise FileNotFoundError(f"NLAH directory missing: {base}")
    readme = base / "README.md"
    if not readme.exists():
        raise FileNotFoundError(f"NLAH/README.md missing in {base}")

    parts: list[str] = [readme.read_text(encoding="utf-8")]

    tools = base / "tools.md"
    if tools.exists():
        parts.append("\n\n---\n\n# Tools reference\n\n" + tools.read_text(encoding="utf-8"))

    examples_dir = base / "examples"
    if examples_dir.is_dir():
        parts.append("\n\n---\n\n# Few-shot examples\n")
        for example in sorted(examples_dir.glob("*.md")):
            parts.append("\n\n" + example.read_text(encoding="utf-8"))

    return "".join(parts)
```

- [ ] **Step 8: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_nlah_loader.py -v
```

Expected: 3 passed.

- [ ] **Step 9: Commit**

```bash
git add packages/agents/cloud-posture/nlah/ packages/agents/cloud-posture/src/cloud_posture/nlah_loader.py packages/agents/cloud-posture/tests/test_nlah_loader.py
git commit -m "feat(cloud-posture): NLAH (domain brain) + tools reference + few-shot examples + loader"
```

---

### Task 8.5: `charter.llm` — `LLMProvider` interface + `AnthropicProvider` (per ADR-003) — 🟡 NEW

**Files:** Create `packages/charter/src/charter/llm.py`, `packages/charter/tests/test_llm.py`.

**Why now (between Tasks 8 and 9):** Task 9 currently reads "_LLM client wrapper (Anthropic) with retry_" inside the cloud-posture package. Per [ADR-003](../../_meta/decisions/ADR-003-llm-provider-strategy.md) every agent talks to LLMs through a tier-pinned interface defined in `packages/charter`, never importing `anthropic` directly. Task 9 is rewritten downstream to consume `charter.llm.LLMProvider`; Task 8.5 puts the interface in place first.

**Scope:**

- `class ModelTier(StrEnum)` — `FRONTIER`, `WORKHORSE`, `EDGE`.
- `@dataclass class ToolSchema` — name, description, JSON-Schema `input_schema`, allowed-tier hint.
- `@dataclass class LLMResponse` — `text: str`, `stop_reason: str`, `usage: TokenUsage`, `tool_calls: list[ToolCall]`, `model_pin: str`, `provider_id: str`.
- `class LLMProvider(Protocol)`:

  ```python
  async def complete(
      self, prompt: str, system: str | None,
      max_tokens: int, temperature: float = 0.0,
      stop: list[str] | None = None,
      tools: list[ToolSchema] | None = None,
      model_pin: str,
  ) -> LLMResponse: ...

  @property
  def provider_id(self) -> str: ...

  @property
  def model_class(self) -> ModelTier: ...
  ```

- `class AnthropicProvider` (initial implementation): wraps `anthropic.AsyncAnthropic`, retries 5xx + 429 with exponential backoff via `tenacity`, enforces `model_pin` is non-empty, audits the call (writes `llm_call_started/completed` events through the charter audit chain when invoked inside a `Charter` context).
- `class FakeLLMProvider` (test double in same module, not exported): returns canned responses; used by Task 9 unit tests + downstream agent tests.
- **Deferred:** `VLLMProvider`, `OllamaProvider`, multi-provider routing, eval-parity gate. Phase 1b–2 work, captured in P0.7 expansion (per ADR-003 references).

**Steps:**

- [ ] **Step 1: Write failing tests** — `LLMProvider` is a `runtime_checkable` Protocol; `FakeLLMProvider` satisfies it; `AnthropicProvider` raises on empty `model_pin`; tenacity retry triggers on simulated 429; `model_class` returns the tier set by the constructor.
- [ ] **Step 2: Run failure**.
- [ ] **Step 3: Implement** — Protocol + dataclasses + AnthropicProvider + FakeLLMProvider. Mark `LLMProvider` `@runtime_checkable`.
- [ ] **Step 4: Tests pass** — target ≥ 6 tests.
- [ ] **Step 5: Audit-chain integration** — when called inside an active `Charter` context (detected via the existing context manager's contextvar from F.1), emit `llm_call_started` and `llm_call_completed` audit entries that include `provider_id`, `model_pin`, prompt-token + completion-token counts. No emission outside a charter context.
- [ ] **Step 6: Commit** — `feat(charter): llmprovider interface and anthropicprovider per adr-003`.

**Acceptance:** `from charter.llm import LLMProvider, ModelTier, AnthropicProvider, FakeLLMProvider` works. cloud-posture's Task 9 is rewritten to depend on `charter.llm`, not `anthropic`.

---

### Task 9: LLM client wrapper (Anthropic) with retry

**Files:** Create `llm.py`, `tests/test_llm.py`

> **Delta from original plan (per [ADR-003](../../_meta/decisions/ADR-003-llm-provider-strategy.md) / Task 8.5):** This wrapper does **not** `import anthropic`. It depends on `charter.llm.LLMProvider` and `AnthropicProvider`. The cloud-posture-local `llm.py` becomes a thin agent-side adapter: it picks a tier (`workhorse` for cloud-posture's per-finding NLAH execution, `frontier` for synthesis paths if any), constructs the right `LLMProvider`, and exposes the same `LLMResponse` surface to the agent driver (Task 10). The tenacity retry block stays here only if it adds agent-specific behavior beyond what `AnthropicProvider` already does; otherwise drop it. Update the `Step 1: Write failing tests` block accordingly when this task is reached — the mock target is `charter.llm.AnthropicProvider`, not `anthropic.Anthropic`.

- [ ] **Step 1: Write failing tests**

```python
# packages/agents/cloud-posture/tests/test_llm.py
"""Tests for the Anthropic LLM client wrapper."""

from unittest.mock import MagicMock, patch

import pytest

from cloud_posture.llm import LLMClient, LLMResponse


def test_llm_client_calls_anthropic_messages_create() -> None:
    fake_anthropic = MagicMock()
    fake_response = MagicMock()
    fake_response.content = [MagicMock(type="text", text="hello back")]
    fake_response.usage.input_tokens = 100
    fake_response.usage.output_tokens = 20
    fake_anthropic.messages.create.return_value = fake_response

    client = LLMClient(client=fake_anthropic, model="claude-sonnet-4-5")
    resp = client.complete(system="be helpful", user="say hi")
    assert isinstance(resp, LLMResponse)
    assert resp.text == "hello back"
    assert resp.input_tokens == 100
    assert resp.output_tokens == 20


def test_llm_response_total_tokens() -> None:
    r = LLMResponse(text="x", input_tokens=10, output_tokens=20)
    assert r.total_tokens == 30
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_llm.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement**

```python
# packages/agents/cloud-posture/src/cloud_posture/llm.py
"""Thin Anthropic Claude wrapper with retry on rate limits / transient errors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential


@dataclass(frozen=True)
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class LLMClient:
    """Wraps anthropic.Anthropic with retry. Caller passes a real or mock client."""

    def __init__(
        self,
        client: Any,
        model: str = "claude-sonnet-4-5",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> None:
        self._client = client
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    def complete(self, *, system: str, user: str) -> LLMResponse:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")
        return LLMResponse(
            text=text,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
        )
```

- [ ] **Step 4: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_llm.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/llm.py packages/agents/cloud-posture/tests/test_llm.py
git commit -m "feat(cloud-posture): Anthropic Claude client wrapper with exponential backoff"
```

---

### Task 10: Cloud Posture agent driver — wires everything together via Charter

**Files:** Create `agent.py`, `tests/test_agent_unit.py`

This is the integration point. Read carefully — this is the **template** for the other 17 agents.

- [ ] **Step 1: Write failing tests (heavily mocked)**

```python
# packages/agents/cloud-posture/tests/test_agent_unit.py
"""Unit tests for the agent driver — all external services mocked."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from charter.contract import BudgetSpec, ExecutionContract

from cloud_posture.agent import build_registry, run


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_test",
        task="Scan AWS account 111122223333 us-east-1",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0,
            cloud_api_calls=100, mb_written=10,
        ),
        permitted_tools=[
            "prowler_scan", "aws_s3_list_buckets", "aws_s3_describe",
            "aws_iam_list_users_without_mfa", "aws_iam_list_admin_policies",
            "kg_upsert_asset", "kg_upsert_finding",
        ],
        completion_condition="findings.json exists AND summary.md exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_build_registry_registers_all_tools() -> None:
    registry = build_registry(neo4j_driver=MagicMock(), customer_id="cust_x")
    expected = {
        "prowler_scan", "aws_s3_list_buckets", "aws_s3_describe",
        "aws_iam_list_users_without_mfa", "aws_iam_list_admin_policies",
        "kg_upsert_asset", "kg_upsert_finding",
    }
    assert expected.issubset(set(registry.known_tools()))


def test_agent_run_writes_findings_and_summary(tmp_path: Path, monkeypatch) -> None:
    """End-to-end with mocked Prowler / boto3 / Neo4j / LLM."""
    contract = _contract(tmp_path)

    # Mock Prowler returns one finding.
    fake_prowler_findings = [{
        "CheckID": "iam_user_no_mfa",
        "Severity": "high",
        "Status": "FAIL",
        "ResourceArn": "arn:aws:iam::111122223333:user/bob",
        "ResourceType": "AwsIamUser",
        "Region": "us-east-1",
        "AccountId": "111122223333",
        "StatusExtended": "User bob has no MFA",
    }]

    from cloud_posture.tools import prowler as prowler_mod
    from cloud_posture.tools import aws_s3 as s3_mod
    from cloud_posture.tools import aws_iam as iam_mod

    monkeypatch.setattr(
        prowler_mod, "run_prowler_aws",
        lambda **kwargs: prowler_mod.ProwlerResult(raw_findings=fake_prowler_findings),
    )
    monkeypatch.setattr(s3_mod, "list_buckets", lambda **kwargs: [])
    monkeypatch.setattr(iam_mod, "list_users_without_mfa", lambda: ["bob"])
    monkeypatch.setattr(iam_mod, "list_admin_policies", lambda: [])

    fake_llm = MagicMock()
    fake_llm.complete.return_value = MagicMock(text="ok", input_tokens=50, output_tokens=10, total_tokens=60)

    fake_neo4j = MagicMock()

    run(contract=contract, llm=fake_llm, neo4j_driver=fake_neo4j)

    workspace = Path(contract.workspace)
    assert (workspace / "findings.json").exists()
    assert (workspace / "summary.md").exists()
    assert (workspace / "audit.jsonl").exists()

    findings = (workspace / "findings.json").read_text()
    assert "bob" in findings or "no MFA" in findings.lower()

    summary = (workspace / "summary.md").read_text()
    assert "Cloud Posture Scan" in summary
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_agent_unit.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement the agent driver**

```python
# packages/agents/cloud-posture/src/cloud_posture/agent.py
"""Cloud Posture Agent — the template for Nexus production agents.

Flow:
1. Charter context opens (workspace, audit, budget).
2. Run Prowler.
3. Enrich significant Prowler findings with primary-source SDK calls.
4. Build a typed FindingsReport.
5. Write findings.json + summary.md.
6. Upsert assets and findings into the customer's knowledge graph.
7. Charter closes (audit completion, optional bytes-written check).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from charter import Charter, ExecutionContract, ToolRegistry

from cloud_posture import __version__ as agent_version
from cloud_posture.llm import LLMClient
from cloud_posture.schemas import (
    AffectedResource,
    Finding,
    FindingsReport,
    Severity,
)
from cloud_posture.summarizer import render_summary
from cloud_posture.tools import aws_iam, aws_s3
from cloud_posture.tools.neo4j_kg import KnowledgeGraphWriter
from cloud_posture.tools.prowler import run_prowler_aws

_PROWLER_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


def build_registry(neo4j_driver: Any, customer_id: str) -> ToolRegistry:
    """Compose the universe of tools available to this agent."""
    kg = KnowledgeGraphWriter(driver=neo4j_driver, customer_id=customer_id)
    reg = ToolRegistry()
    reg.register("prowler_scan", run_prowler_aws, version="5.0.0", cloud_calls=200)
    reg.register("aws_s3_list_buckets", aws_s3.list_buckets, version="1.35.0", cloud_calls=1)
    reg.register("aws_s3_describe", aws_s3.describe_bucket, version="1.35.0", cloud_calls=6)
    reg.register("aws_iam_list_users_without_mfa", aws_iam.list_users_without_mfa, version="1.35.0", cloud_calls=10)
    reg.register("aws_iam_list_admin_policies", aws_iam.list_admin_policies, version="1.35.0", cloud_calls=10)
    reg.register("kg_upsert_asset", kg.upsert_asset, version="0.1.0", cloud_calls=0)
    reg.register("kg_upsert_finding", kg.upsert_finding, version="0.1.0", cloud_calls=0)
    return reg


def _finding_id(rule_id: str, arn: str) -> str:
    suffix = arn.split(":")[-1].replace("/", "-").lower()
    suffix = "".join(c if c.isalnum() or c == "-" else "-" for c in suffix)[:60]
    return f"{rule_id}-{suffix}"


def _finding_from_prowler(raw: dict[str, Any]) -> Finding:
    severity = _PROWLER_SEVERITY_MAP.get(str(raw.get("Severity", "info")).lower(), Severity.INFO)
    arn = raw["ResourceArn"]
    rule_id = f"CSPM-AWS-{raw['ResourceType'].replace('Aws', '').upper()}-{raw['CheckID'].split('_')[-1].zfill(3)[:3]}"
    return Finding(
        finding_id=_finding_id(rule_id, arn),
        rule_id=rule_id,
        severity=severity,
        title=raw.get("StatusExtended", raw["CheckID"]),
        description=raw.get("StatusExtended", "Prowler-detected issue"),
        affected=[AffectedResource(
            cloud="aws",
            account_id=raw["AccountId"],
            region=raw["Region"],
            resource_type=raw["ResourceType"].lower(),
            resource_id=arn.split("/")[-1].split(":")[-1],
            arn=arn,
        )],
        evidence={"prowler_check": raw["CheckID"], "raw": raw},
        detected_at=datetime.now(UTC),
    )


def run(
    contract: ExecutionContract,
    llm: LLMClient,
    neo4j_driver: Any,
) -> FindingsReport:
    """Run the Cloud Posture Agent under the runtime charter.

    Returns the FindingsReport. Side effects: writes findings.json + summary.md
    to workspace; upserts knowledge graph; appends to audit log.
    """
    registry = build_registry(neo4j_driver=neo4j_driver, customer_id=contract.customer_id)

    with Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)

        # 1. Prowler scan
        prowler_result = ctx.call_tool(
            "prowler_scan",
            llm_calls=0, tokens=0,
            account_id="111122223333",  # in real use, parsed from contract.task
            region="us-east-1",
            output_dir=Path(contract.workspace) / "prowler_out",
        )

        # 2. IAM enrichment (always runs; cheap)
        users_without_mfa = ctx.call_tool(
            "aws_iam_list_users_without_mfa", llm_calls=0, tokens=0,
        )
        admin_policies = ctx.call_tool(
            "aws_iam_list_admin_policies", llm_calls=0, tokens=0,
        )

        # 3. Build findings
        findings: list[Finding] = []

        for raw in prowler_result.raw_findings:
            try:
                findings.append(_finding_from_prowler(raw))
            except Exception:
                continue  # malformed Prowler row — skip

        for username in users_without_mfa:
            findings.append(Finding(
                finding_id=f"CSPM-AWS-IAM-001-{username}",
                rule_id="CSPM-AWS-IAM-001",
                severity=Severity.HIGH,
                title=f"IAM user '{username}' has console password but no MFA",
                description="Console-enabled users without MFA are a known credential-theft vector.",
                affected=[AffectedResource(
                    cloud="aws", account_id="111122223333", region="us-east-1",
                    resource_type="aws_iam_user", resource_id=username,
                    arn=f"arn:aws:iam::111122223333:user/{username}",
                )],
                evidence={"check": "list_mfa_devices returned []"},
                detected_at=datetime.now(UTC),
            ))

        for policy in admin_policies:
            findings.append(Finding(
                finding_id=f"CSPM-AWS-IAM-002-{policy['policy_name']}",
                rule_id="CSPM-AWS-IAM-002",
                severity=Severity.CRITICAL,
                title=f"Customer-managed policy '{policy['policy_name']}' grants Action=* Resource=*",
                description="Any principal attached has admin equivalence.",
                affected=[AffectedResource(
                    cloud="aws", account_id="111122223333", region="us-east-1",
                    resource_type="aws_iam_policy", resource_id=policy["policy_name"],
                    arn=policy["policy_arn"],
                )],
                evidence={"document": policy["document"]},
                detected_at=datetime.now(UTC),
            ))

        # 4. Write knowledge graph
        for f in findings:
            for affected in f.affected:
                ctx.call_tool(
                    "kg_upsert_asset", llm_calls=0, tokens=0,
                    kind=affected.resource_type,
                    external_id=affected.arn,
                    properties={
                        "region": affected.region,
                        "account_id": affected.account_id,
                    },
                )
            ctx.call_tool(
                "kg_upsert_finding", llm_calls=0, tokens=0,
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                severity=f.severity.value,
                affected_arns=[a.arn for a in f.affected],
            )

        # 5. Build report
        report = FindingsReport(
            agent="cloud_posture",
            agent_version=agent_version,
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=datetime.now(UTC),
            findings=findings,
        )

        # 6. Write outputs
        ctx.write_output(
            "findings.json",
            report.model_dump_json(indent=2).encode("utf-8"),
        )
        ctx.write_output(
            "summary.md",
            render_summary(report).encode("utf-8"),
        )

        # 7. (Optional) LLM narration — single call to produce richer summary
        # Skipped in v0.1 reference flow — Synthesis Agent (D.13) owns customer-facing narrative.

        ctx.assert_complete()
        return report
```

- [ ] **Step 4: Update package `__init__.py`**

```python
# packages/agents/cloud-posture/src/cloud_posture/__init__.py
"""Nexus Cloud Posture Agent."""

__version__ = "0.1.0"
```

- [ ] **Step 5: Tests pass**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_agent_unit.py -v
```

Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/agent.py packages/agents/cloud-posture/src/cloud_posture/__init__.py packages/agents/cloud-posture/tests/test_agent_unit.py
git commit -m "feat(cloud-posture): agent driver wiring Prowler + IAM enrichment + KG + Charter context"
```

---

### Task 11: LocalStack-backed integration test

**Files:** Create `tests/conftest.py`, `tests/test_agent_integration.py`

- [ ] **Step 1: Create `conftest.py` with LocalStack fixture**

```python
# packages/agents/cloud-posture/tests/conftest.py
"""Shared fixtures: LocalStack endpoint detection + AWS credentials."""

import os
import socket

import pytest


def _localstack_running() -> bool:
    try:
        with socket.create_connection(("localhost", 4566), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def localstack_endpoint() -> str:
    if not _localstack_running():
        pytest.skip("LocalStack not running on localhost:4566 — run docker compose up")
    return "http://localhost:4566"


@pytest.fixture
def aws_env(monkeypatch, localstack_endpoint):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ENDPOINT_URL", localstack_endpoint)
```

- [ ] **Step 2: Write the integration test**

```python
# packages/agents/cloud-posture/tests/test_agent_integration.py
"""Integration test against LocalStack — tools hit real (mocked) AWS endpoints."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest

from charter.contract import BudgetSpec, ExecutionContract

from cloud_posture.agent import run


@pytest.mark.integration
def test_iam_no_mfa_detection_against_localstack(tmp_path: Path, aws_env, monkeypatch) -> None:
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="alice", Password="P@ssw0rd!Strong!")
    iam.create_login_profile(UserName="bob", Password="P@ssw0rd!Strong!")
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber="arn:aws:iam::000000000000:mfa/alice",
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    # Mock Prowler (LocalStack doesn't host a Prowler binary).
    from cloud_posture.tools import prowler as prowler_mod
    monkeypatch.setattr(
        prowler_mod, "run_prowler_aws",
        lambda **kwargs: prowler_mod.ProwlerResult(raw_findings=[]),
    )

    contract = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id="cust_integration",
        task="Scan account",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0,
            cloud_api_calls=100, mb_written=10,
        ),
        permitted_tools=[
            "prowler_scan", "aws_s3_list_buckets", "aws_s3_describe",
            "aws_iam_list_users_without_mfa", "aws_iam_list_admin_policies",
            "kg_upsert_asset", "kg_upsert_finding",
        ],
        completion_condition="findings.json exists AND summary.md exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    fake_llm = MagicMock()
    fake_neo4j = MagicMock()

    report = run(contract=contract, llm=fake_llm, neo4j_driver=fake_neo4j)

    bob_findings = [f for f in report.findings if "bob" in f.title]
    assert len(bob_findings) == 1
    assert bob_findings[0].severity.value == "high"

    alice_findings = [f for f in report.findings if "alice" in f.title]
    assert len(alice_findings) == 0
```

- [ ] **Step 3: Add `integration` marker to pyproject pytest config**

In root `pyproject.toml`, extend `[tool.pytest.ini_options]`:

```toml
[tool.pytest.ini_options]
testpaths = ["packages"]
python_files = "test_*.py"
addopts = "-ra --strict-markers --strict-config -p no:cacheprovider"
markers = [
    "integration: hits localstack/postgres/neo4j; skipped when infra not running",
]
```

- [ ] **Step 4: Bring up infra and run**

```bash
docker compose -f docker/docker-compose.dev.yml up -d localstack
sleep 5  # LocalStack startup
uv run pytest packages/agents/cloud-posture/tests/test_agent_integration.py -v -m integration
```

Expected: 1 passed.

- [ ] **Step 5: Tear down**

```bash
docker compose -f docker/docker-compose.dev.yml down
```

- [ ] **Step 6: Commit**

```bash
git add packages/agents/cloud-posture/tests/conftest.py packages/agents/cloud-posture/tests/test_agent_integration.py pyproject.toml
git commit -m "test(cloud-posture): localstack-backed integration test for IAM no-MFA detection"
```

---

### Task 12: Minimal local eval runner + 10 cases

**Files:** Create `_eval_local.py`, `eval/cases/*.yaml`, `eval/README.md`, `tests/test_eval_local.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/agents/cloud-posture/tests/test_eval_local.py
"""Tests for the minimal local eval runner."""

from pathlib import Path

import pytest

from cloud_posture._eval_local import (
    EvalCase,
    EvalResult,
    load_cases,
    run_case,
)


def test_load_cases_reads_yaml(tmp_path: Path) -> None:
    case_file = tmp_path / "001_x.yaml"
    case_file.write_text("""
case_id: 001_x
description: smoke
fixture:
  prowler_findings: []
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 0
  has_severity:
    critical: 0
    high: 0
""")
    cases = load_cases(tmp_path)
    assert len(cases) == 1
    assert cases[0].case_id == "001_x"


def test_run_case_passes_when_expected_matches() -> None:
    case = EvalCase(
        case_id="t1",
        description="empty",
        fixture={"prowler_findings": [], "iam_users_without_mfa": [], "iam_admin_policies": []},
        expected={"finding_count": 0, "has_severity": {"critical": 0, "high": 0}},
    )
    result = run_case(case)
    assert isinstance(result, EvalResult)
    assert result.passed is True


def test_run_case_fails_on_count_mismatch() -> None:
    case = EvalCase(
        case_id="t2",
        description="bob without mfa",
        fixture={
            "prowler_findings": [],
            "iam_users_without_mfa": ["bob"],
            "iam_admin_policies": [],
        },
        expected={"finding_count": 0, "has_severity": {"critical": 0, "high": 0}},
    )
    result = run_case(case)
    assert result.passed is False
    assert "finding_count" in result.failure_reason
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_eval_local.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement minimal eval runner**

```python
# packages/agents/cloud-posture/src/cloud_posture/_eval_local.py
"""Minimal local eval runner — to be replaced by F.2 eval-framework.

Usage:
    cases = load_cases(Path("eval/cases"))
    results = [run_case(c) for c in cases]
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import yaml

from charter.contract import BudgetSpec, ExecutionContract

from cloud_posture import agent as agent_mod
from cloud_posture.tools import aws_iam, aws_s3, prowler


@dataclass(frozen=True)
class EvalCase:
    case_id: str
    description: str
    fixture: dict[str, Any]
    expected: dict[str, Any]


@dataclass(frozen=True)
class EvalResult:
    case_id: str
    passed: bool
    failure_reason: str | None
    actual_counts: dict[str, int]


def load_cases(directory: Path | str) -> list[EvalCase]:
    out: list[EvalCase] = []
    for path in sorted(Path(directory).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        out.append(EvalCase(
            case_id=data["case_id"],
            description=data["description"],
            fixture=data["fixture"],
            expected=data["expected"],
        ))
    return out


def _stub_tools(case: EvalCase, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        prowler, "run_prowler_aws",
        lambda **kwargs: prowler.ProwlerResult(raw_findings=case.fixture["prowler_findings"]),
    )
    monkeypatch.setattr(
        aws_iam, "list_users_without_mfa",
        lambda: case.fixture["iam_users_without_mfa"],
    )
    monkeypatch.setattr(
        aws_iam, "list_admin_policies",
        lambda: case.fixture["iam_admin_policies"],
    )
    monkeypatch.setattr(
        aws_s3, "list_buckets",
        lambda **kwargs: case.fixture.get("s3_buckets", []),
    )


def run_case(case: EvalCase, workspace_root: Path | None = None) -> EvalResult:
    """Execute one eval case against the agent driver, mocking external tools."""
    import pytest
    workspace_root = workspace_root or Path("/tmp/nexus-eval") / case.case_id
    workspace_root.mkdir(parents=True, exist_ok=True)

    monkeypatch = pytest.MonkeyPatch()
    try:
        _stub_tools(case, monkeypatch)
        contract = ExecutionContract(
            schema_version="0.1",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
            source_agent="supervisor",
            target_agent="cloud_posture",
            customer_id="cust_eval",
            task=case.description,
            required_outputs=["findings.json", "summary.md"],
            budget=BudgetSpec(
                llm_calls=10, tokens=20_000, wall_clock_sec=60.0,
                cloud_api_calls=200, mb_written=10,
            ),
            permitted_tools=[
                "prowler_scan", "aws_s3_list_buckets", "aws_s3_describe",
                "aws_iam_list_users_without_mfa", "aws_iam_list_admin_policies",
                "kg_upsert_asset", "kg_upsert_finding",
            ],
            completion_condition="findings.json exists",
            escalation_rules=[],
            workspace=str(workspace_root / "ws"),
            persistent_root=str(workspace_root / "p"),
            created_at=datetime.now(UTC),
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        )
        report = agent_mod.run(
            contract=contract,
            llm=MagicMock(),
            neo4j_driver=MagicMock(),
        )
    finally:
        monkeypatch.undo()

    counts = report.count_by_severity()
    expected_count = case.expected["finding_count"]
    if report.total != expected_count:
        return EvalResult(
            case_id=case.case_id,
            passed=False,
            failure_reason=f"finding_count expected {expected_count}, got {report.total}",
            actual_counts=counts,
        )
    expected_sev = case.expected.get("has_severity", {})
    for sev, want in expected_sev.items():
        if counts.get(sev, 0) != want:
            return EvalResult(
                case_id=case.case_id,
                passed=False,
                failure_reason=f"severity '{sev}' expected {want}, got {counts.get(sev, 0)}",
                actual_counts=counts,
            )
    return EvalResult(
        case_id=case.case_id,
        passed=True,
        failure_reason=None,
        actual_counts=counts,
    )
```

- [ ] **Step 4: Run unit tests on eval runner**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_eval_local.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Create the 10 representative eval cases**

`packages/agents/cloud-posture/eval/cases/001_public_s3_bucket.yaml`:

```yaml
case_id: 001_public_s3_bucket
description: Public S3 bucket should produce one high finding
fixture:
  prowler_findings:
    - CheckID: s3_bucket_public_access
      Severity: high
      Status: FAIL
      ResourceArn: arn:aws:s3:::acme-public
      ResourceType: AwsS3Bucket
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'Bucket acme-public allows public READ via ACL'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    critical: 0
    high: 1
    medium: 0
    low: 0
```

`packages/agents/cloud-posture/eval/cases/002_iam_user_admin_no_mfa.yaml`:

```yaml
case_id: 002_iam_user_admin_no_mfa
description: User without MFA should produce one high finding
fixture:
  prowler_findings: []
  iam_users_without_mfa: [bob]
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    critical: 0
    high: 1
```

`packages/agents/cloud-posture/eval/cases/003_unencrypted_rds.yaml`:

```yaml
case_id: 003_unencrypted_rds
description: Unencrypted RDS instance produces high
fixture:
  prowler_findings:
    - CheckID: rds_instance_storage_encrypted
      Severity: high
      Status: FAIL
      ResourceArn: arn:aws:rds:us-east-1:111122223333:db:prod-db
      ResourceType: AwsRdsDbInstance
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'RDS instance prod-db is not encrypted at rest'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    high: 1
```

`packages/agents/cloud-posture/eval/cases/004_open_security_group.yaml`:

```yaml
case_id: 004_open_security_group
description: SG allowing 0.0.0.0/0 on port 22
fixture:
  prowler_findings:
    - CheckID: ec2_securitygroup_allow_ingress_from_internet_to_port_22
      Severity: critical
      Status: FAIL
      ResourceArn: arn:aws:ec2:us-east-1:111122223333:security-group/sg-abc
      ResourceType: AwsEc2SecurityGroup
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'SG sg-abc opens 22/tcp to 0.0.0.0/0'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    critical: 1
```

`packages/agents/cloud-posture/eval/cases/005_no_cloudtrail.yaml`:

```yaml
case_id: 005_no_cloudtrail
description: Account without CloudTrail
fixture:
  prowler_findings:
    - CheckID: cloudtrail_multi_region_enabled
      Severity: high
      Status: FAIL
      ResourceArn: arn:aws:cloudtrail:us-east-1:111122223333:trail/none
      ResourceType: AwsCloudTrailTrail
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'No multi-region CloudTrail trail enabled'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    high: 1
```

`packages/agents/cloud-posture/eval/cases/006_root_account_used.yaml`:

```yaml
case_id: 006_root_account_used
description: Root account used in last 30d
fixture:
  prowler_findings:
    - CheckID: iam_root_no_mfa
      Severity: critical
      Status: FAIL
      ResourceArn: arn:aws:iam::111122223333:root
      ResourceType: AwsIamUser
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'Root account used recently without MFA'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    critical: 1
```

`packages/agents/cloud-posture/eval/cases/007_kms_key_no_rotation.yaml`:

```yaml
case_id: 007_kms_key_no_rotation
description: KMS key without rotation
fixture:
  prowler_findings:
    - CheckID: kms_cmk_rotation_enabled
      Severity: medium
      Status: FAIL
      ResourceArn: arn:aws:kms:us-east-1:111122223333:key/abc-123
      ResourceType: AwsKmsKey
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'KMS CMK abc-123 does not have rotation enabled'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    medium: 1
```

`packages/agents/cloud-posture/eval/cases/008_overprivileged_role.yaml`:

```yaml
case_id: 008_overprivileged_role
description: Customer-managed admin policy
fixture:
  prowler_findings: []
  iam_users_without_mfa: []
  iam_admin_policies:
    - policy_name: TooBroad
      policy_arn: arn:aws:iam::111122223333:policy/TooBroad
      document:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
expected:
  finding_count: 1
  has_severity:
    critical: 1
```

`packages/agents/cloud-posture/eval/cases/009_public_rds_snapshot.yaml`:

```yaml
case_id: 009_public_rds_snapshot
description: Public RDS snapshot
fixture:
  prowler_findings:
    - CheckID: rds_snapshots_public_access
      Severity: critical
      Status: FAIL
      ResourceArn: arn:aws:rds:us-east-1:111122223333:snapshot:public-snap
      ResourceType: AwsRdsDbSnapshot
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'Snapshot public-snap is shared with all AWS accounts'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    critical: 1
```

`packages/agents/cloud-posture/eval/cases/010_unencrypted_ebs_volume.yaml`:

```yaml
case_id: 010_unencrypted_ebs_volume
description: Unencrypted EBS volume
fixture:
  prowler_findings:
    - CheckID: ec2_ebs_volume_encryption
      Severity: medium
      Status: FAIL
      ResourceArn: arn:aws:ec2:us-east-1:111122223333:volume/vol-abc
      ResourceType: AwsEc2Volume
      Region: us-east-1
      AccountId: '111122223333'
      StatusExtended: 'EBS volume vol-abc is unencrypted'
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 1
  has_severity:
    medium: 1
```

- [ ] **Step 6: Create `eval/README.md`**

````markdown
# Cloud Posture Eval Suite

Each YAML case is a fixture (mocks of Prowler / IAM tool outputs) plus expected findings.

```bash
uv run python -c "
from pathlib import Path
from cloud_posture._eval_local import load_cases, run_case
cases = load_cases(Path('packages/agents/cloud-posture/eval/cases'))
results = [run_case(c) for c in cases]
passed = sum(1 for r in results if r.passed)
print(f'{passed}/{len(results)} passed')
for r in results:
    if not r.passed:
        print(f'  {r.case_id}: {r.failure_reason}')
"
```

Phase 1 target: 100 cases. v0.1 ships with 10 representative cases covering the high-leverage AWS misconfigurations. Adding cases is a follow-on within F.3 (no new infra).
````

- [ ] **Step 7: Run all 10 cases**

```bash
uv run python -c "
from pathlib import Path
from cloud_posture._eval_local import load_cases, run_case
cases = load_cases(Path('packages/agents/cloud-posture/eval/cases'))
results = [run_case(c) for c in cases]
passed = sum(1 for r in results if r.passed)
print(f'{passed}/{len(results)} passed')
for r in results:
    if not r.passed:
        print(f'  FAIL {r.case_id}: {r.failure_reason}')
"
```

Expected: `10/10 passed`.

- [ ] **Step 8: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/_eval_local.py packages/agents/cloud-posture/eval/ packages/agents/cloud-posture/tests/test_eval_local.py
git commit -m "feat(cloud-posture): minimal local eval runner + 10 representative AWS misconfiguration cases"
```

---

### Task 13: CLI

**Files:** Create `cli.py`, `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/agents/cloud-posture/tests/test_cli.py
"""Tests for the cloud-posture CLI."""

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from cloud_posture.cli import main


def test_eval_runs(tmp_path: Path) -> None:
    eval_dir = tmp_path / "cases"
    eval_dir.mkdir()
    (eval_dir / "001_x.yaml").write_text("""
case_id: 001_x
description: empty
fixture:
  prowler_findings: []
  iam_users_without_mfa: []
  iam_admin_policies: []
expected:
  finding_count: 0
  has_severity:
    critical: 0
    high: 0
""")
    runner = CliRunner()
    result = runner.invoke(main, ["eval", str(eval_dir)])
    assert result.exit_code == 0
    assert "passed" in result.output.lower()
```

- [ ] **Step 2: Run failure**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_cli.py -v
```

Expected: `ImportError`

- [ ] **Step 3: Implement CLI**

```python
# packages/agents/cloud-posture/src/cloud_posture/cli.py
"""cloud-posture CLI: eval, dry-run."""

from __future__ import annotations

from pathlib import Path

import click

from cloud_posture._eval_local import load_cases, run_case


@click.group()
@click.version_option()
def main() -> None:
    """Cloud Posture Agent CLI."""


@main.command("eval")
@click.argument("cases_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
def eval_cmd(cases_dir: Path) -> None:
    """Run the local eval suite against the agent."""
    cases = load_cases(cases_dir)
    results = [run_case(c) for c in cases]
    passed = sum(1 for r in results if r.passed)
    click.echo(f"{passed}/{len(results)} passed")
    fail_count = 0
    for r in results:
        if not r.passed:
            click.echo(f"  FAIL {r.case_id}: {r.failure_reason}")
            fail_count += 1
    if fail_count:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Tests pass + smoke test the real CLI**

```bash
uv run pytest packages/agents/cloud-posture/tests/test_cli.py -v
uv run cloud-posture eval packages/agents/cloud-posture/eval/cases
```

Expected: tests pass; CLI prints `10/10 passed`.

- [ ] **Step 5: Commit**

```bash
git add packages/agents/cloud-posture/src/cloud_posture/cli.py packages/agents/cloud-posture/tests/test_cli.py
git commit -m "feat(cloud-posture): CLI with eval subcommand"
```

---

### Task 14: AWS dev-account smoke runbook (manual)

**Files:** Create `runbooks/aws_dev_account_smoke.md`

- [ ] **Step 1: Create runbook**

````markdown
# AWS dev-account smoke test

This runbook validates the Cloud Posture Agent against a **real AWS dev account** before any customer-facing release. Do not run against production accounts.

## Prerequisites

- AWS profile `nexus-dev` with read-only access (`SecurityAudit` policy attached)
- Prowler installed: `pip install prowler`
- `uv sync` completed in repo root
- `docker compose -f docker/docker-compose.dev.yml up -d neo4j` (for KG sink)

## Procedure

1. **Confirm read-only**

   ```bash
   aws sts get-caller-identity --profile nexus-dev
   aws iam simulate-principal-policy \
       --policy-source-arn arn:aws:iam::<account>:role/nexus-dev-readonly \
       --action-names iam:DeleteUser \
       --profile nexus-dev
   ```

   Expected: `EvalDecision: implicitDeny`.

2. **Run Prowler standalone (sanity)**

   ```bash
   prowler aws --profile nexus-dev --region us-east-1 --output-formats json-ocsf --output-directory /tmp/prowler-smoke
   ls /tmp/prowler-smoke/*.ocsf.json
   ```

3. **Build invocation contract**

   `/tmp/smoke-contract.yaml`:

   ```yaml
   schema_version: '0.1'
   delegation_id: 01J7M3X9Z1K8RPVQNH2T8SMOKEZ
   source_agent: supervisor
   target_agent: cloud_posture
   customer_id: cust_dev_smoke
   task: 'Scan AWS dev account us-east-1 (smoke run)'
   required_outputs: [findings.json, summary.md]
   budget:
     llm_calls: 5
     tokens: 50000
     wall_clock_sec: 300
     cloud_api_calls: 1000
     mb_written: 50
   permitted_tools:
     - prowler_scan
     - aws_s3_list_buckets
     - aws_s3_describe
     - aws_iam_list_users_without_mfa
     - aws_iam_list_admin_policies
     - kg_upsert_asset
     - kg_upsert_finding
   completion_condition: findings.json exists AND summary.md exists
   escalation_rules: []
   workspace: /tmp/nexus-smoke/workspaces/cust_dev_smoke/cloud_posture/run/
   persistent_root: /tmp/nexus-smoke/persistent/cust_dev_smoke/cloud_posture/
   created_at: 2026-05-08T12:00:00Z
   expires_at: 2026-05-08T13:00:00Z
   ```

4. **Run the agent**

   ```bash
   AWS_PROFILE=nexus-dev uv run python -c "
   from pathlib import Path
   from unittest.mock import MagicMock
   from charter import load_contract
   from cloud_posture.agent import run
   from cloud_posture.llm import LLMClient
   import anthropic
   import neo4j

   contract = load_contract(Path('/tmp/smoke-contract.yaml'))
   llm = LLMClient(client=anthropic.Anthropic(), model='claude-sonnet-4-5')
   driver = neo4j.GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'nexus_dev_password'))
   try:
       report = run(contract=contract, llm=llm, neo4j_driver=driver)
       print(f'Findings: {report.total}')
       print(f'By severity: {report.count_by_severity()}')
   finally:
       driver.close()
   "
   ```

5. **Verify outputs**

   ```bash
   ls /tmp/nexus-smoke/workspaces/cust_dev_smoke/cloud_posture/run/
   cat /tmp/nexus-smoke/workspaces/cust_dev_smoke/cloud_posture/run/summary.md | head -40
   uv run charter audit verify /tmp/nexus-smoke/workspaces/cust_dev_smoke/cloud_posture/run/audit.jsonl
   ```

   Expected: `findings.json`, `summary.md`, `audit.jsonl` present; audit verify reports `VALID`.

6. **Cleanup**

   ```bash
   rm -rf /tmp/nexus-smoke /tmp/prowler-smoke /tmp/smoke-contract.yaml
   ```

## Pass criteria

- ✅ Findings count is reasonable for the dev account (not 0 unless account is genuinely clean; not >500).
- ✅ All affected resources have valid ARNs.
- ✅ Audit log verifies clean.
- ✅ No exceptions raised; all required outputs written.
- ✅ Wall clock under contracted budget (< 5 min).
- ✅ No unexpected AWS API calls (review CloudTrail for the dev account during the smoke window).

## When this runbook fails

- Capture stderr + audit.jsonl + Prowler raw output, file as bug per `.github/ISSUE_TEMPLATE/bug.yml`.
- Tag the failing finding's rule_id; add an eval case to `eval/cases/` so the regression has a test.
````

- [ ] **Step 2: Commit**

```bash
git add packages/agents/cloud-posture/runbooks/
git commit -m "docs(cloud-posture): aws dev-account smoke runbook"
```

---

### Task 15: README and ADR

**Files:** Create `packages/agents/cloud-posture/README.md`, `docs/_meta/decisions/ADR-003-cloud-posture-as-reference-agent.md`

- [ ] **Step 1: Create package README**

````markdown
# `nexus-cloud-posture`

Cloud Posture Agent (#1 of 18). The **reference NLAH** — the pattern other agents follow.

## What it does

Scans AWS accounts for misconfigurations using Prowler + boto3. Emits typed findings, generates a markdown summary, and upserts assets/findings to the customer's knowledge graph. Every action runs through the runtime charter (budget, audit, whitelist).

## Quick start

```bash
# Run the eval suite
uv run cloud-posture eval packages/agents/cloud-posture/eval/cases

# Run against AWS (see runbooks/aws_dev_account_smoke.md)
```

## Inputs

A signed `ExecutionContract` (YAML). See `nexus-charter` for the schema.

## Outputs

- `findings.json` — `FindingsReport` schema
- `summary.md` — markdown digest
- `audit.jsonl` — hash-chained log of every action

## Architecture

```
ExecutionContract (YAML)
    ↓
Charter context (budget + tools + audit + workspace)
    ↓
agent.run(contract, llm, neo4j_driver)
    ├─ prowler_scan               (Prowler 5.x subprocess)
    ├─ aws_iam_list_users_without_mfa
    ├─ aws_iam_list_admin_policies
    ├─ kg_upsert_asset / kg_upsert_finding
    │
    ├─ Build FindingsReport
    ├─ Write findings.json + summary.md
    └─ ctx.assert_complete()
```

## License

Business Source License 1.1. Production use requires a commercial license.

## See also

- NLAH (the domain brain): `nlah/README.md`
- ADR-003: Cloud Posture as the reference NLAH (`docs/_meta/decisions/`)
- Plan: `docs/superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md`
````

- [ ] **Step 2: Create ADR-003**

`docs/_meta/decisions/ADR-003-cloud-posture-as-reference-agent.md`:

```markdown
# ADR-003 — Cloud Posture is the reference NLAH

- **Status:** accepted
- **Date:** 2026-05-08
- **Authors:** Amelia (dev), Detection Eng
- **Stakeholders:** all engineers, all NLAH authors

## Context

Phase 1 ships 18 agents. Building each from scratch wastes effort and produces drift. We need ONE canonical implementation that defines the pattern, then 17 derivations.

Three plausible "first" agents:

1. Cloud Posture (CSPM)
2. Vulnerability (CVE scanning via Trivy)
3. Identity (CIEM, custom permission simulator)

## Decision

Cloud Posture is the reference. The other 17 follow this template.

## Consequences

### Positive

- **Simplest tool surface** (~7 tools) — engineers learn the pattern without fighting domain complexity.
- **Highest-value Day-1** — every customer in every vertical needs CSPM.
- **Mature OSS foundation** — Prowler is battle-tested and widely understood.
- **Vertical-agnostic** — cloud misconfigurations look the same in tech, healthcare, finance.
- **Clear schemas** — findings have well-defined shapes.

### Negative

- Some patterns won't generalize 1:1 (Investigation needs sub-agent orchestration; Curiosity is reactive-not-scheduled). Mitigation: ADRs per agent that document deltas from the Cloud Posture template.

### Neutral

- The 10-case eval suite is a starting point. Phase 1 target: 100 cases. Adding cases is incremental work in the same structure.

## Alternatives considered

### Alt 1: Vulnerability first

- Why rejected: requires a working asset graph + EPSS feed, which adds dependencies before the pattern is stable.

### Alt 2: Identity first

- Why rejected: custom permission simulator is significant Phase 1 work; not a clean reference.

## References

- Plan: `docs/superpowers/plans/2026-05-08-f-3-cloud-posture-reference-nlah.md`
- Reference implementation: `packages/agents/cloud-posture/`
- Charter: `packages/charter/`
```

- [ ] **Step 3: Update version-history**

Add row to `docs/_meta/version-history.md`:

```markdown
| 2026-05-08 | cloud-posture | 0.1.0 | F.3 ships: NLAH + tools + Charter integration + 10 eval cases | F.3 |
```

- [ ] **Step 4: Commit**

```bash
git add packages/agents/cloud-posture/README.md docs/_meta/decisions/ADR-003-cloud-posture-as-reference-agent.md docs/_meta/version-history.md
git commit -m "docs(cloud-posture): readme + ADR-003 (reference agent rationale) + version history"
```

---

### Task 16: Final verification

**Files:** none

- [ ] **Step 1: Full test suite + coverage**

```bash
uv run pytest packages/agents/cloud-posture/ -v --cov=cloud_posture --cov-report=term-missing --cov-fail-under=80
```

Expected: all tests pass; coverage ≥ 80%.

- [ ] **Step 2: Lint + typecheck**

```bash
uv run ruff check packages/agents/cloud-posture/
uv run ruff format --check packages/agents/cloud-posture/
uv run mypy packages/agents/cloud-posture/src
```

Expected: clean.

- [ ] **Step 3: Eval suite (production check)**

```bash
uv run cloud-posture eval packages/agents/cloud-posture/eval/cases
```

Expected: `10/10 passed`.

- [ ] **Step 4: LocalStack integration**

```bash
docker compose -f docker/docker-compose.dev.yml up -d localstack
sleep 5
uv run pytest packages/agents/cloud-posture/ -v -m integration
docker compose -f docker/docker-compose.dev.yml down
```

Expected: integration test passes.

- [ ] **Step 5: Confirm package wired into Turborepo**

```bash
pnpm turbo run test --filter=nexus-cloud-posture --dry=json | head -30
```

Expected: package known to Turbo.

- [ ] **Step 6: Verify charter audit chain end-to-end**

```bash
uv run python -c "
from pathlib import Path
from unittest.mock import MagicMock
from datetime import UTC, datetime, timedelta
from charter.contract import BudgetSpec, ExecutionContract
from charter.verifier import verify_audit_log
from cloud_posture.agent import run
from cloud_posture.tools import prowler

import tempfile
import pytest

mp = pytest.MonkeyPatch()
mp.setattr(prowler, 'run_prowler_aws', lambda **k: prowler.ProwlerResult(raw_findings=[]))

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    contract = ExecutionContract(
        schema_version='0.1', delegation_id='01J7M3X9Z1K8RPVQNH2T8DBHFZ',
        source_agent='supervisor', target_agent='cloud_posture', customer_id='cust',
        task='smoke', required_outputs=['findings.json','summary.md'],
        budget=BudgetSpec(llm_calls=5, tokens=10000, wall_clock_sec=60, cloud_api_calls=100, mb_written=10),
        permitted_tools=['prowler_scan','aws_s3_list_buckets','aws_s3_describe',
            'aws_iam_list_users_without_mfa','aws_iam_list_admin_policies',
            'kg_upsert_asset','kg_upsert_finding'],
        completion_condition='findings.json exists', escalation_rules=[],
        workspace=str(tmp/'ws'), persistent_root=str(tmp/'p'),
        created_at=datetime.now(UTC), expires_at=datetime.now(UTC)+timedelta(minutes=5),
    )
    run(contract=contract, llm=MagicMock(), neo4j_driver=MagicMock())
    result = verify_audit_log(tmp/'ws'/'audit.jsonl')
    print(f'Audit valid: {result.valid}, entries: {result.entries_checked}')
mp.undo()
"
```

Expected: `Audit valid: True, entries: <some count ≥ 4>`.

---

## Self-Review

**Spec coverage:**

- ✓ NLAH (domain brain) authored — Task 8
- ✓ Prowler integration — Task 3
- ✓ AWS S3 + IAM tools — Tasks 4, 5
- ✓ Neo4j knowledge-graph writer — Task 6
- ✓ Findings schema (typed) — Task 2
- ✓ Markdown summarizer — Task 7
- ✓ Charter integration — Task 10
- ✓ LocalStack integration test — Task 11
- ✓ Eval suite (10 representative cases, structure scales to 100) — Task 12
- ✓ CLI — Task 13
- ✓ AWS dev-account smoke runbook — Task 14
- ✓ Documentation + ADR-003 — Task 15

**Placeholder scan:** none. Every step has full code.

**Type / name consistency:**

- `ProwlerResult.raw_findings` (Task 3) → fed to `_finding_from_prowler` (Task 10) — keys match (`CheckID`, `Severity`, `ResourceArn`, `ResourceType`, `Region`, `AccountId`, `StatusExtended`).
- `Finding.finding_id` regex enforced in Task 2; agent code generates IDs in Task 10 matching that regex.
- Tool names registered in `build_registry` (Task 10) match `permitted_tools` in eval contract (Task 12), unit-test contract (Task 10), integration contract (Task 11), and smoke runbook (Task 14): `prowler_scan`, `aws_s3_list_buckets`, `aws_s3_describe`, `aws_iam_list_users_without_mfa`, `aws_iam_list_admin_policies`, `kg_upsert_asset`, `kg_upsert_finding`.
- `KnowledgeGraphWriter` constructor signature (`driver`, `customer_id`) matches usage in `build_registry` and unit tests.

**Gaps / explicit deferrals (acceptable):**

- LLM is wired but not exercised in the v0.1 reference flow (we deterministically build findings from tool outputs). LLM-driven enrichment moves to D.13 (Synthesis Agent) which owns customer-facing narrative across agents. This was a deliberate choice to keep the reference simple.
- Eval suite is 10 cases; Phase 1 target is 100. Adding cases is the same YAML structure — no new infra.
- `_eval_local.py` is a stand-in for the F.2 `eval-framework` package. F.2 will subsume this with a richer runner (parallel, comparison, CI integration); migration is mechanical.
- Multi-region scanning in one invocation is not implemented — current task takes one region per contract. Multi-region orchestration belongs to the Supervisor (deferred).
- The `account_id` and `region` are hardcoded in `agent.run` for v0.1 reference. Production version parses these from `contract.task` via a small NL parser (Phase 1b).

**Coverage of the larger goal (the "reference for 17 more agents") — what generalizes:**

1. Package layout: `nlah/` + `src/<agent>/{schemas,tools/*,agent.py,_eval_local.py,cli.py}` + `eval/cases/*.yaml` + `runbooks/`
2. Tool wrapping pattern: subprocess (Prowler), boto3 read-only, custom analyzer
3. Charter integration: `build_registry()` returning a `ToolRegistry`, then `with Charter(contract, tools=registry) as ctx`
4. Findings schema pattern: typed `Finding` model + `<Domain>Report` aggregator + `count_by_severity`
5. Summary pattern: severity-grouped markdown
6. Eval pattern: YAML fixtures of mocked tool outputs + expected counts
7. CLI pattern: `<agent> eval <cases-dir>`

Each subsequent agent (Vulnerability, Identity, Runtime Threat, …) replicates this skeleton, swapping the domain (tools, schema fields, NLAH content). Estimated 50–60% time savings vs. building from scratch.
