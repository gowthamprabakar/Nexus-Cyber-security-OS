"""Smoke test — package imports."""

import charter


def test_charter_imports() -> None:
    assert charter.__version__ == "0.1.0"
