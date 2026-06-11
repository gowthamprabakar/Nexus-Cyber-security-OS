"""D.6 v0.2 Task 4 — CIS K8s Benchmark v1.8 catalog tests."""

from __future__ import annotations

from k8s_posture.cis.benchmark import (
    BENCHMARK_VERSION,
    CIS_K8S_V18,
    CisControl,
    cis_level,
    lookup,
)


def test_benchmark_version_is_1_8() -> None:
    assert BENCHMARK_VERSION == "1.8"


def test_lookup_known_control() -> None:
    c = lookup("1.2.1")
    assert isinstance(c, CisControl)
    assert c.level == 1 and "anonymous-auth" in c.title


def test_lookup_unknown_returns_none() -> None:
    assert lookup("9.9.9") is None


def test_cis_level() -> None:
    assert cis_level("5.2.2") == 2  # privileged containers — level 2
    assert cis_level("1.2.1") == 1
    assert cis_level("9.9.9") is None


def test_catalog_spans_multiple_sections() -> None:
    sections = {cid.split(".", 1)[0] for cid in CIS_K8S_V18}
    # control plane (1), etcd (2), config (3), worker (4), policies (5).
    assert {"1", "2", "3", "4", "5"} <= sections


def test_all_levels_are_1_or_2() -> None:
    assert all(c.level in (1, 2) for c in CIS_K8S_V18.values())


def test_broader_than_v1_5_subset() -> None:
    # v1.8 expansion includes 5.x policy controls absent from the v0.1 subset.
    assert "5.3.2" in CIS_K8S_V18 and "5.2.6" in CIS_K8S_V18
