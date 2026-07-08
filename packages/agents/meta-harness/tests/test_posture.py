from meta_harness import posture as P
from meta_harness.attack_paths import _SEVERITY


def test_bucket_of_boundaries():
    assert P.bucket_of(100) == "critical"
    assert P.bucket_of(90) == "critical"
    assert P.bucket_of(89) == "high"
    assert P.bucket_of(75) == "high"
    assert P.bucket_of(74) == "medium"
    assert P.bucket_of(50) == "medium"
    assert P.bucket_of(49) == "low"
    assert P.bucket_of(0) == "low"


def test_path_domain_is_complete_and_valid():
    # Every live path_type must map to a real domain — no silent "other".
    for path_type in _SEVERITY:
        assert path_type in P.PATH_DOMAIN, f"unmapped path_type: {path_type}"
        assert P.PATH_DOMAIN[path_type] in P.DOMAINS, f"bad domain for {path_type}"


def test_domain_categories_cover_all_domains():
    assert set(P.DOMAIN_CATEGORIES) == set(P.DOMAINS)
