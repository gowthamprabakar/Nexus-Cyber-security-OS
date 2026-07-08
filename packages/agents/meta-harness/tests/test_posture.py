import json
from datetime import UTC, datetime

import pytest
from charter.memory.graph_types import NodeCategory as NC
from fleet_testkit import in_memory_semantic_store
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


class _Feeder:
    def __init__(self, ok: bool) -> None:
        self.ok = ok


@pytest.mark.asyncio
async def test_count_categories_counts_per_type():
    async with in_memory_semantic_store() as store:
        await store.upsert_entity(
            tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-1", properties={}
        )
        await store.upsert_entity(
            tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-2", properties={}
        )
        await store.upsert_entity(
            tenant_id="t", entity_type=NC.IDENTITY.value, external_id="id-1", properties={}
        )
        counts = await P.count_categories(
            store, "t", (NC.CVE_FINDING.value, NC.IDENTITY.value, NC.SECRET_FINDING.value)
        )
        assert counts == {NC.CVE_FINDING.value: 2, NC.IDENTITY.value: 1, NC.SECRET_FINDING.value: 0}


@pytest.mark.asyncio
async def test_compute_coverage_domain_collector_surfaced():
    async with in_memory_semantic_store() as store:
        # 1 finding entity that IS on a path (surfaced), 1 that is NOT
        f1 = await store.upsert_entity(
            tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-1", properties={}
        )
        await store.upsert_entity(
            tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-2", properties={}
        )
        await store.upsert_entity(
            tenant_id="t", entity_type=NC.IDENTITY.value, external_id="id-1", properties={}
        )
        counts = await P.count_categories(store, "t", P._all_counted())
        paths = [_p("internet_exposed_vulnerable", 80, entities=(f1,))]
        feeders = [_Feeder(True), _Feeder(True), _Feeder(False)]
        cov = await P.compute_coverage(store, "t", paths, feeders, category_counts=counts)
        # domains covered: vulnerability (CVE) + identity (IDENTITY) = 2 of 9
        assert cov.domains_covered == 2 and cov.domains_total == 9 and cov.domain_pct == 22
        assert cov.collectors_ok == 2 and cov.collectors_run == 3 and cov.collector_pct == 67
        assert cov.surfaced_findings == 1 and cov.total_findings == 2 and cov.surfaced_pct == 50


@pytest.mark.asyncio
async def test_compute_coverage_no_feeders_is_none_and_guards_zero():
    async with in_memory_semantic_store() as store:
        counts = await P.count_categories(store, "t", P._all_counted())
        cov = await P.compute_coverage(store, "t", [], None, category_counts=counts)
        assert cov.collectors_ok is None and cov.collector_pct is None
        assert cov.total_findings == 0 and cov.surfaced_pct == 0 and cov.domain_pct == 0


@pytest.mark.asyncio
async def test_compute_full_summary_on_fixture():
    async with in_memory_semantic_store() as store:
        f1 = await store.upsert_entity(
            tenant_id="t", entity_type=NC.CVE_FINDING.value, external_id="cve-1", properties={}
        )
        await store.upsert_entity(
            tenant_id="t", entity_type=NC.CLOUD_RESOURCE.value, external_id="arn:x", properties={}
        )
        paths = [
            _p("crown_jewel", 95, entities=(f1,)),
            _p("internet_exposed_vulnerable", 80, kev=True, epss=0.9, entities=(f1,)),
        ]
        now = datetime(2026, 7, 8, tzinfo=UTC)
        s = await P.PostureRollup(store, "t").compute(now=now, paths=paths, feeders=[_Feeder(True)])
        assert s.tenant == "t" and s.scan_at == now.isoformat()
        assert s.totals["attack_paths"] == 2
        assert s.severity_distribution == {"critical": 1, "high": 1, "medium": 0, "low": 0}
        assert s.exposure_funnel.exposed == 1 and s.exposure_funnel.kev == 1
        assert s.coverage.surfaced_findings == 1 and s.coverage.collectors_ok == 1
        assert s.inventory_counts[NC.CLOUD_RESOURCE.value] == 1


@pytest.mark.asyncio
async def test_compute_empty_graph_is_all_zero():
    async with in_memory_semantic_store() as store:
        s = await P.PostureRollup(store, "t").compute(
            now=datetime(2026, 7, 8, tzinfo=UTC), paths=[], feeders=[]
        )
        assert s.totals["attack_paths"] == 0
        assert s.severity_distribution == {"critical": 0, "high": 0, "medium": 0, "low": 0}
        assert s.by_domain == () and s.by_path_type == () and s.top_paths == ()
        assert s.coverage.domain_pct == 0 and s.coverage.surfaced_pct == 0


@pytest.mark.asyncio
async def test_write_posture_json_round_trips(tmp_path):
    async with in_memory_semantic_store() as store:
        s = await P.PostureRollup(store, "t").compute(
            now=datetime(2026, 7, 8, tzinfo=UTC), paths=[], feeders=[]
        )
        path = P.write_posture_json(s, tmp_path)
        assert path == tmp_path / "aggregation" / "posture.json"
        data = json.loads(path.read_text())
        assert (
            data["tenant"] == "t"
            and "coverage" in data
            and data["severity_distribution"]["critical"] == 0
        )


def test_render_leads_with_coverage_and_omits_missing_collectors():
    cov = P.Coverage(4, 9, 44, None, None, None, 3, 10, 30)
    s = P.PostureSummary(
        tenant="t",
        scan_at="2026-07-08T00:00:00+00:00",
        coverage=cov,
        totals={"attack_paths": 5, "findings": 10, "nodes": 20},
        severity_distribution={"critical": 1, "high": 2, "medium": 1, "low": 1},
        by_domain=(P.DomainCount("data", 1, 0, 0, 0, 1),),
        by_path_type=(),
        exposure_funnel=P.ExposureFunnel(2, 2, 1, 1),
        inventory_counts={},
        top_paths=(),
    )
    md = P.render_posture_summary(s)
    first_line = md.strip().splitlines()[0]
    assert "Coverage" in first_line and "44%" in first_line
    assert "collector" not in md.lower()  # omitted when None
    assert "data" in md
