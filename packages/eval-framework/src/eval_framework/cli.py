"""Stub for the `eval-framework` CLI.

This file is intentionally minimal until Task 13 of the F.2 plan ships the
real Click-based command group (run / compare / gate). The stub exists
so the `[project.scripts]` entry point in pyproject.toml resolves cleanly
during `uv sync` — without it, every install would dangle.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Placeholder — replaced by Task 13."""
    sys.stderr.write(
        "eval-framework CLI is not yet implemented (F.2 Task 13 pending). "
        "Use the Python API for now: from eval_framework import …\n"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
