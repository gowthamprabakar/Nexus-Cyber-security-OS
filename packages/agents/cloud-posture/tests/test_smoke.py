"""Smoke test — package imports."""

import cloud_posture


def test_cloud_posture_imports() -> None:
    assert cloud_posture.__version__ == "0.1.0"
