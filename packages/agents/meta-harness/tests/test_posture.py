from meta_harness import posture as P
from meta_harness.attack_paths import _SEVERITY, AttackPath


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


def _p(path_type, severity, *, kev=False, epss=None, entities=("e",)):
    return AttackPath(
        path_type=path_type, severity=severity, title="t", entities=entities, kev=kev, epss=epss
    )


def test_severity_distribution_counts_by_bucket():
    paths = [
        _p("crown_jewel", 95),
        _p("public_secret", 90),
        _p("lateral_movement", 82),
        _p("fine_grained_data", 60),
    ]
    assert P.severity_distribution(paths) == {"critical": 2, "high": 1, "medium": 1, "low": 0}


def test_by_path_type_counts_and_max_severity():
    paths = [_p("crown_jewel", 95), _p("crown_jewel", 80), _p("public_secret", 90)]
    got = {c.path_type: (c.count, c.max_severity) for c in P.by_path_type(paths)}
    assert got == {"crown_jewel": (2, 95), "public_secret": (1, 90)}


def test_by_domain_groups_paths_into_domains():
    paths = [
        _p("crown_jewel", 95),
        _p("exposed_database", 84),
        _p("public_secret", 90),
    ]  # data, data, identity
    rows = {d.domain: d for d in P.by_domain(paths)}
    assert rows["data"].total == 2 and rows["data"].critical == 1 and rows["data"].high == 1
    assert rows["identity"].total == 1 and rows["identity"].critical == 1
    assert "network" not in rows  # domains with no paths are omitted


def test_exposure_funnel():
    paths = [
        _p("internet_exposed_vulnerable", 80, kev=True, epss=0.9),
        _p("internet_exposed_vulnerable", 80, kev=False, epss=0.2),
        _p("internet_exposed_host_vulnerable", 79, kev=False, epss=None),
        _p("crown_jewel", 95),  # not an exposure path — excluded
    ]
    f = P.exposure_funnel(paths)
    assert (f.exposed, f.vulnerable, f.kev, f.exploitable) == (3, 3, 1, 1)
