"""Per-agent shim — delegates to `charter.nlah_loader` (ADR-007 v1.2).

The canonical loader lives in [`charter.nlah_loader`](../../../../charter/src/charter/nlah_loader.py).
This shim binds the agent's own `__file__` so legacy callers keep
their zero-argument `default_nlah_dir()` API:

    from identity.nlah_loader import default_nlah_dir, load_system_prompt
    nlah_dir = default_nlah_dir()         # -> .../identity/nlah/
    prompt = load_system_prompt()         # default dir, full concat

Tests can still pass an explicit `nlah_dir` to exercise the loader
against synthetic content.
"""

from __future__ import annotations

from pathlib import Path

from charter.nlah_loader import default_nlah_dir as _resolve_default_dir
from charter.nlah_loader import load_system_prompt as _load


def default_nlah_dir() -> Path:
    """Path to the NLAH directory shipped inside this package."""
    return _resolve_default_dir(__file__)


def load_system_prompt(nlah_dir: Path | str | None = None) -> str:
    """Build the LLM system prompt from this package's NLAH dir.

    Pass `nlah_dir` to override (tests + customer-specific NLAH overrides
    deferred to Phase 1b).
    """
    return _load(nlah_dir if nlah_dir is not None else default_nlah_dir())


__all__ = ["default_nlah_dir", "load_system_prompt"]
