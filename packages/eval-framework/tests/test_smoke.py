"""Smoke test — package imports."""

import eval_framework


def test_eval_framework_imports() -> None:
    assert eval_framework.__version__ == "0.1.0"
