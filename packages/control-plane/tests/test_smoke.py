"""Smoke test — package imports."""

import control_plane


def test_control_plane_imports() -> None:
    assert control_plane.__version__ == "0.1.0"
