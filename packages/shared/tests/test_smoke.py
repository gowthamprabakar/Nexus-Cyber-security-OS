"""Smoke test — package imports."""

import shared


def test_shared_imports() -> None:
    assert shared.__version__ == "0.1.0"
