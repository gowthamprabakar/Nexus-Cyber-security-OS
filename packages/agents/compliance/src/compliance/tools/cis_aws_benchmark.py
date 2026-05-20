"""``read_cis_aws_benchmark`` — filesystem ingest for the bundled CIS AWS YAML.

Loads the CIS AWS Foundations Benchmark v3.0 control library that ships
inside the package at ``compliance.control_libraries.cis_aws_v3.yaml``
(arrives in Task 4). Per ADR-005 the filesystem read happens on
``asyncio.to_thread``; the wrapper is ``async`` for TaskGroup fan-out
from the agent driver (Task 11).

**Operator workflow.** v0.1 ships the framework library bundled --
operators do NOT stage external snapshots. Production callers pass
:func:`default_cis_aws_v3_path` to read the bundled file. v0.2 lifts
this so customer-pinned framework overrides (e.g., a vertical-specific
SOC2 control subset) can override individual controls via the same
loader signature.

**Wire shape (YAML).** Top-level mapping:

.. code-block:: yaml

    framework: cis_aws_v3
    version: '3.0.0'
    controls:
      - control_id: '1.1'
        name: Avoid the use of the root user
        level: level_1
        applicability: [aws_iam, aws_root_account]
        required: true
        description: >-
          Paraphrased operator-facing summary. v0.1 contains no
          verbatim CIS text (Q6).
        source_mappings:
          - source_agent: cloud_posture
            source_rule_id: iam_root_account_use
          - source_agent: data_security
            source_rule_id: root_user_with_data_access

The ``source_mappings`` field carries
:class:`compliance.schemas.ControlMapping`-shaped records but with the
``control_id`` / ``level`` / ``required`` fields elided -- those come
from the enclosing control entry. The loader materialises full
``ControlMapping`` instances by folding the enclosing control's
metadata in.

**Forgiving** on malformed control entries -- bad entries are dropped
silently with a structured-log warning. Raises
``CisAwsBenchmarkReaderError`` on missing file, bad file type, or
malformed top-level YAML.

**Q6 reminder.** This loader carries no verbatim CIS Benchmark text.
The bundled YAML (Task 4) ships paraphrased descriptions written
in-house from public CIS metadata. The loader exposes those
descriptions to operator-facing surfaces (Task 10 summarizer +
Task 14 CLI digest) verbatim.
"""

from __future__ import annotations

import asyncio
import logging
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from compliance.schemas import ControlLevel, ControlMapping

_LOG = logging.getLogger(__name__)


class CisAwsBenchmarkReaderError(RuntimeError):
    """The CIS AWS Benchmark YAML library could not be read."""


class CisControl(BaseModel):
    """One parsed CIS AWS Benchmark v3.0 control entry.

    Surfaces the fields the correlators (Tasks 6 + 7) + aggregator
    (Task 8) + scorer (Task 9) + summarizer (Task 10) need to map
    sibling-agent findings to compliance controls and report posture.

    Q6 reminder: ``description`` is the paraphrased operator-facing
    summary written in-house. It is NOT lifted from the CIS PDF /
    Securesuite materials.
    """

    control_id: str = Field(min_length=1, max_length=20)
    name: str = Field(min_length=1)
    level: ControlLevel
    applicability: tuple[str, ...] = Field(default_factory=tuple)
    required: bool = True
    description: str = ""
    source_mappings: tuple[ControlMapping, ...] = Field(default_factory=tuple)

    @field_validator("control_id")
    @classmethod
    def _check_control_id(cls, value: str) -> str:
        # CIS control IDs are dotted decimals like "1.1" or "2.1.5"; the
        # canonical shape is digit-only-with-dots. We don't enforce the
        # exact CIS numbering here (the YAML is the source of truth)
        # but we reject obviously-bad shapes.
        if not value.replace(".", "").isdigit():
            raise ValueError(f"control_id must be a dotted decimal (got {value!r})")
        return value


def default_cis_aws_v3_path() -> Path:
    """Return the path to the bundled CIS AWS v3 YAML (Task 4)."""
    pkg = resources.files("compliance.control_libraries")
    candidate = pkg / "cis_aws_v3.yaml"
    return Path(str(candidate))


async def read_cis_aws_benchmark(*, path: Path | None = None) -> tuple[CisControl, ...]:
    """Read the CIS AWS Benchmark v3.0 YAML and return the parsed controls.

    When ``path`` is ``None``, the bundled library at
    :func:`default_cis_aws_v3_path` is used. Raises
    :class:`CisAwsBenchmarkReaderError` if the file is missing, not a
    file, or malformed YAML. Individual control entries that fail
    pydantic validation are dropped silently.

    The reader is pure I/O.
    """
    target = path if path is not None else default_cis_aws_v3_path()
    return await asyncio.to_thread(_read_sync, target)


def _read_sync(path: Path) -> tuple[CisControl, ...]:
    if not path.exists():
        raise CisAwsBenchmarkReaderError(f"CIS AWS benchmark library not found: {path}")
    if not path.is_file():
        raise CisAwsBenchmarkReaderError(f"CIS AWS benchmark library is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise CisAwsBenchmarkReaderError(
            f"CIS AWS benchmark library is malformed YAML: {exc}"
        ) from exc

    if not isinstance(blob, dict):
        raise CisAwsBenchmarkReaderError(
            f"CIS AWS benchmark library top-level must be a YAML mapping at {path}"
        )

    raw_controls = blob.get("controls", [])
    if not isinstance(raw_controls, list):
        raise CisAwsBenchmarkReaderError(
            f"CIS AWS benchmark library 'controls' field must be a list at {path}"
        )

    out: list[CisControl] = []
    for raw in raw_controls:
        record = _try_parse(raw)
        if record is not None:
            out.append(record)
    return tuple(out)


def _try_parse(raw: Any) -> CisControl | None:
    """Parse one YAML control entry into a CisControl + nested mappings."""
    if not isinstance(raw, dict):
        return None

    control_id = raw.get("control_id")
    level = raw.get("level")
    if not isinstance(control_id, str) or not control_id:
        return None
    if not isinstance(level, str) or not level:
        return None

    try:
        level_enum = ControlLevel(level)
    except ValueError:
        _LOG.warning("dropping CIS control %s — unknown level %r", control_id, level)
        return None

    required = bool(raw.get("required", True))
    raw_mappings = raw.get("source_mappings", []) or []
    if not isinstance(raw_mappings, list):
        raw_mappings = []

    mappings: list[ControlMapping] = []
    for m in raw_mappings:
        if not isinstance(m, dict):
            continue
        source_agent = m.get("source_agent")
        source_rule_id = m.get("source_rule_id")
        if not isinstance(source_agent, str) or not source_agent:
            continue
        if not isinstance(source_rule_id, str) or not source_rule_id:
            continue
        # Override-or-inherit semantics: the YAML mapping entry MAY
        # carry its own `level` + `required`; otherwise inherit from
        # the enclosing control.
        entry_level_raw = m.get("level")
        if isinstance(entry_level_raw, str):
            try:
                entry_level = ControlLevel(entry_level_raw)
            except ValueError:
                entry_level = level_enum
        else:
            entry_level = level_enum
        entry_required = bool(m.get("required", required))
        mappings.append(
            ControlMapping(
                source_agent=source_agent,
                source_rule_id=source_rule_id,
                control_id=control_id,
                level=entry_level,
                required=entry_required,
            )
        )

    raw_applicability = raw.get("applicability", []) or []
    applicability: tuple[str, ...]
    if isinstance(raw_applicability, list):
        applicability = tuple(str(a) for a in raw_applicability if isinstance(a, str) and a)
    else:
        applicability = ()

    try:
        return CisControl(
            control_id=control_id,
            name=str(raw.get("name", "")),
            level=level_enum,
            applicability=applicability,
            required=required,
            description=str(raw.get("description", "")),
            source_mappings=tuple(mappings),
        )
    except ValidationError:
        _LOG.warning("dropping CIS control %s — pydantic validation failed", control_id)
        return None
    except (TypeError, ValueError, KeyError):
        return None


__all__ = [
    "CisAwsBenchmarkReaderError",
    "CisControl",
    "default_cis_aws_v3_path",
    "read_cis_aws_benchmark",
]
