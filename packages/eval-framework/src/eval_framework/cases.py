"""Eval case model — typed wrapper over a YAML fixture + expected pair.

The full YAML loader lives in `eval_framework.cases` after Task 3; for now
this module ships only the typed model so other modules can import it.
"""

from __future__ import annotations

from typing import Any

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
