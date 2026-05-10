"""Stub for the `identity-agent` CLI.

Replaced by the real Click command group in D.2 Task 14. The stub exists
so the `[project.scripts]` entry point in pyproject.toml resolves cleanly
during `uv sync` — without it, every install would dangle.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Placeholder — replaced by D.2 Task 14."""
    sys.stderr.write(
        "identity-agent CLI is not yet implemented (D.2 Task 14 pending). "
        "Use the Python API for now: from identity import …\n"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
