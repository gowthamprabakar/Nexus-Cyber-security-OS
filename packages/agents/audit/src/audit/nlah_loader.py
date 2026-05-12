"""Per-agent NLAH shim — delegates to `charter.nlah_loader` (ADR-007 v1.2).

Binds the agent's own `__file__` so the zero-argument `default_nlah_dir()`
API stays intact. Mirrors D.3's post-v1.2 shape.
"""

from __future__ import annotations

from pathlib import Path

from charter.nlah_loader import default_nlah_dir as _resolve_default_dir
from charter.nlah_loader import load_system_prompt as _load


def default_nlah_dir() -> Path:
    """Path to the NLAH directory shipped inside this package."""
    return _resolve_default_dir(__file__)


def load_system_prompt(nlah_dir: Path | str | None = None) -> str:
    """Build the LLM system prompt from this package's NLAH dir."""
    return _load(nlah_dir if nlah_dir is not None else default_nlah_dir())


__all__ = ["default_nlah_dir", "load_system_prompt"]
