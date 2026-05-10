"""Eval cases — typed model + YAML loader.

A case is the smallest unit of eval work: a fixture (mocked tool outputs
the runner will see) plus an expected shape (counts, severity bands, free-
form keys the runner interprets). Files are YAML; the framework owns the
schema, individual agents own the keys inside `fixture` and `expected`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class EvalCase(BaseModel):
    """One eval fixture: tool outputs in, expected finding shape out.

    `fixture` and `expected` are deliberately untyped (`dict[str, Any]`) at
    the framework level — agents interpret their own keys (e.g.
    cloud-posture's `prowler_findings`, `iam_users_without_mfa`,
    `iam_admin_policies`). The framework itself only orchestrates.
    """

    case_id: str = Field(min_length=1)
    description: str
    fixture: dict[str, Any] = Field(default_factory=dict)
    expected: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    timeout_sec: float = Field(default=60.0, gt=0.0)

    model_config = ConfigDict(frozen=True)


def load_case_file(path: Path | str) -> EvalCase:
    """Parse one YAML file into a validated `EvalCase`.

    Raises:
        FileNotFoundError: the path does not exist.
        ValueError: the file is empty or contains malformed YAML.
        pydantic.ValidationError: the YAML is well-formed but missing
            required fields or has invalid types.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"case file not found: {p}")

    raw = p.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ValueError(f"failed to parse YAML at {p}: {e}") from e

    if data is None:
        raise ValueError(f"case file is empty: {p}")
    if not isinstance(data, dict):
        raise ValueError(
            f"case file must be a YAML mapping at the top level, got {type(data).__name__}: {p}"
        )

    return EvalCase.model_validate(data)


def load_cases(directory: Path | str) -> list[EvalCase]:
    """Load every `*.yaml` file in `directory` into validated `EvalCase`s.

    Files are sorted lexicographically (filesystem ordering varies by
    platform; sorting makes runs deterministic). Non-`*.yaml` files are
    ignored. Duplicate `case_id` across files raises `ValueError`.

    Raises:
        FileNotFoundError: the directory does not exist or is not a directory.
        ValueError: malformed YAML, empty file, or duplicate case_id.
        pydantic.ValidationError: for any file failing the EvalCase schema.
    """
    d = Path(directory)
    if not d.is_dir():
        raise FileNotFoundError(f"cases directory not found: {d}")

    out: list[EvalCase] = []
    seen: dict[str, Path] = {}
    for path in sorted(d.glob("*.yaml")):
        case = load_case_file(path)
        if case.case_id in seen:
            raise ValueError(f"duplicate case_id {case.case_id!r}: {seen[case.case_id]} and {path}")
        seen[case.case_id] = path
        out.append(case)
    return out
