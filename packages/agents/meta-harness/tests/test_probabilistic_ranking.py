"""v0.5 Item 1 — end-to-end: expected-loss ranking + noisy-OR at the report-card level."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery
from meta_harness.path_priors import EDGE_TRAVERSAL_PRIOR
from meta_harness.report_card import build_report_card, rank_by_expected_loss
from vulnerability.kg_writer import KnowledgeGraphWriter as VulnKgWriter
from vulnerability.tools.trivy import TrivyResult


async def _public_data(store, t, res, dt="ssn"):
    b = await store.upsert_entity(
        tenant_id=t,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=res,
        properties={"is_public": True},
    )
    d = await store.upsert_entity(
        tenant_id=t,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{res}/d",
        properties={"data_type": dt},
    )
    await store.add_relationship(
        tenant_id=t,
        src_entity_id=b,
        dst_entity_id=d,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return b, d


@pytest.mark.asyncio
async def test_no_duplicate_card_for_generic_can_escalate_to_when_named_hit_exists() -> None:
    """FIX #1: _generic_path_type must return 'escalation_method_to_data' (not 'privilege_escalation')
    so the dedup bucket check in build_report_card matches the named detector's path_type and
    suppresses the generic candidate.  Without the fix, the customer sees two cards for the same
    principal→target→data path (one named 'escalation_method_to_data', one 'privilege_escalation').
    """
    t = "dedup-escalation"
    async with in_memory_semantic_store() as store:
        # Principal with external_trust=True so the generic walker starts from it as a graph source.
        principal = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:aws:iam::1:user/attacker",
            properties={"external_trust": True},
        )
        target = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:aws:iam::1:role/admin",
            properties={},
        )
        resource = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:s3:::crown",
            properties={"is_public": True},
        )
        data = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="arn:aws:s3:::crown/ssn",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=principal,
            dst_entity_id=target,
            relationship_type=EdgeType.CAN_ESCALATE_TO.value,
            properties={"method": "self_grant_admin"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=target,
            dst_entity_id=resource,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=resource,
            dst_entity_id=data,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        cards = await build_report_card(store, t)
        escalation_cards = [
            c for c in cards if c.path_type in {"escalation_method_to_data", "privilege_escalation"}
        ]
        # There must be exactly ONE card that covers this principal's escalation path to the data.
        # Before the fix: the generic engine returned "privilege_escalation" — different bucket from
        # the named detector's "escalation_method_to_data" → dedup missed it → count was 2.
        assert len(escalation_cards) == 1, (
            f"Expected 1 escalation card but got {len(escalation_cards)}: "
            f"{[c.path_type for c in escalation_cards]}"
        )
        assert escalation_cards[0].path_type == "escalation_method_to_data"


@pytest.mark.asyncio
async def test_higher_blast_radius_ranks_higher_at_equal_probability() -> None:
    t = "loss-order"
    async with in_memory_semantic_store() as store:
        ident = IdentityKgWriter(store, t)
        # admin A reaches 3 data stores; admin B reaches 1 — same path type, A has higher expected loss
        for res in ("arn:a1", "arn:a2", "arn:a3"):
            await _public_data(store, t, res)
            await ident.record_access([("arn:aws:iam::1:role/A", res)])
        await _public_data(store, t, "arn:b1")
        await ident.record_access([("arn:aws:iam::1:role/B", "arn:b1")])
        cards = await build_report_card(store, t)
        a = max(c.expected_loss for c in cards if "role/A" in " ".join(c.chain))
        b = max(c.expected_loss for c in cards if "role/B" in " ".join(c.chain))
        assert a > b


@pytest.mark.asyncio
async def test_edge_prior_table_is_load_bearing(monkeypatch) -> None:
    # Mutating the expert prior must change a generic path's probability -> guards dead config.
    # Uses an external-identity source (external_trust=True) so the named lateral_reachable
    # detector (which only walks CLOUD_RESOURCE is_public=True footholds) does NOT fire —
    # the path stays a GENERIC candidate whose probability uses route_probability(EDGE_TRAVERSAL_PRIOR).
    t = "load-bearing"
    async with in_memory_semantic_store() as store:
        # a novel 2-hop generic path: external_identity -CAN_REACH-> host -VULNERABLE_TO-> cve
        p = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:ext-principal",
            properties={"external_trust": True},
        )
        h = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:host",
            properties={},
        )
        c = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-1",
            properties={"severity": "HIGH"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=p,
            dst_entity_id=h,
            relationship_type=EdgeType.CAN_REACH.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=h,
            dst_entity_id=c,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        base = await build_report_card(store, t)
        base_p = max((card.probability for card in base), default=0.0)
        # belief.py imported EDGE_TRAVERSAL_PRIOR by reference — an in-place setitem on the shared
        # object is seen by route_probability. (setattr-rebind would NOT be: belief holds the old obj.)
        monkeypatch.setitem(EDGE_TRAVERSAL_PRIOR, "CAN_REACH", 0.01)
        bumped = await build_report_card(store, t)
        bumped_p = max((card.probability for card in bumped), default=0.0)
        assert bumped_p < base_p  # lowering the CAN_REACH prior lowered the path probability


@pytest.mark.asyncio
async def test_kev_dominates() -> None:
    # KEV boosts generic-path probability via leaf_probability floor (§4.4); named paths can't
    # carry KEV — this asymmetry is by design, so we test GENERIC paths only (§4.5).
    # Uses external-identity sources (external_trust=True) so the named lateral_reachable
    # detector (which only walks CLOUD_RESOURCE is_public=True footholds) does NOT fire —
    # these paths stay GENERIC, where route_probability carries the KEV signal.
    t = "kev-dominates"
    async with in_memory_semantic_store() as store:
        # path A: external_identity -CAN_REACH-> hostA -VULNERABLE_TO-> CVE-A (kev=True, severity=HIGH)
        pubA = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:ext-A",
            properties={"external_trust": True},
        )
        hostA = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:hostA",
            properties={},
        )
        cveA = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-A",
            properties={"severity": "HIGH", "kev": True},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=pubA,
            dst_entity_id=hostA,
            relationship_type=EdgeType.CAN_REACH.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=hostA,
            dst_entity_id=cveA,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        # path B: external_identity -CAN_REACH-> hostB -VULNERABLE_TO-> CVE-B (kev=False, severity=HIGH)
        pubB = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:ext-B",
            properties={"external_trust": True},
        )
        hostB = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:hostB",
            properties={},
        )
        cveB = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-B",
            properties={"severity": "HIGH", "kev": False},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=pubB,
            dst_entity_id=hostB,
            relationship_type=EdgeType.CAN_REACH.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=hostB,
            dst_entity_id=cveB,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        cards = await build_report_card(store, t)
        kev_card = next(c for c in cards if "arn:hostA" in c.chain)
        non_kev_card = next(c for c in cards if "arn:hostB" in c.chain)
        # KEV floor raises leaf_probability to ≥0.9 vs ~0.66 for non-KEV HIGH severity.
        assert kev_card.probability > non_kev_card.probability


@pytest.mark.asyncio
async def test_find_stored_secret_to_data_fires_for_non_public_workload() -> None:
    """FIX #3: find_stored_secret_to_data intentionally fires for ANY workload that stores a
    secret — not just public ones.  The NAMED_SHAPES entry carries 'public_resource' only to
    suppress the generic-engine duplicate when the workload happens to be a graph source (public).
    A private workload is a real threat (attacker inside the workload inherits the embedded
    credential's blast radius), so the detector must NOT be narrowed to is_public=True.
    """
    t = "stored-secret-non-public"
    async with in_memory_semantic_store() as store:
        # Non-public workload (no is_public property) stores a secret whose owner can reach data.
        workload = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:ecs::1:task/worker",
            properties={},  # deliberately NOT is_public=True
        )
        secret = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.SECRET.value,
            external_id="secret:api-key-123",
            properties={"secret_type": "api_key"},
        )
        owner = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.IDENTITY.value,
            external_id="arn:aws:iam::1:role/worker-role",
            properties={},
        )
        data_resource = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:s3:::sensitive-bucket",
            properties={"is_public": True},
        )
        dc = await store.upsert_entity(
            tenant_id=t,
            entity_type=NodeCategory.DATA_CLASSIFICATION.value,
            external_id="arn:aws:s3:::sensitive-bucket/pii",
            properties={"data_type": "ssn"},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=workload,
            dst_entity_id=secret,
            relationship_type=EdgeType.STORES_SECRET.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=secret,
            dst_entity_id=owner,
            relationship_type=EdgeType.OWNED_BY.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=owner,
            dst_entity_id=data_resource,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=data_resource,
            dst_entity_id=dc,
            relationship_type=EdgeType.EXPOSES_DATA.value,
            properties={},
        )
        hits = await KgQuery(store, t).find_stored_secret_to_data()
        # The non-public workload MUST produce a hit — proving the broad scope is intentional.
        assert len(hits) == 1, (
            "find_stored_secret_to_data must detect secrets in non-public workloads; "
            f"got {len(hits)} hits"
        )
        assert hits[0].workload_id == workload
        assert hits[0].secret_id == secret
        assert hits[0].data_type == "ssn"


# ---------------------------------------------------------------------------
# Task 2: KEV flows through the REAL writer into the ranking (anti-regression)
# ---------------------------------------------------------------------------

_IMAGE_KEV = "myreg/kev-workload:1.0"
_IMAGE_PLAIN = "myreg/plain-workload:1.0"
_CVE_KEV_ID = "CVE-2021-44228"  # the KEV-listed CVE (Log4Shell)
_CVE_PLAIN_ID = "CVE-2022-99999"  # same severity, NOT KEV-listed


def _trivy_finding(*, cve_id: str, image_ref: str, severity: str = "HIGH") -> dict:
    """One raw Trivy finding, shaped like the real scanner's output."""
    return {
        "VulnerabilityID": cve_id,
        "PkgName": "test-pkg",
        "InstalledVersion": "1.0.0",
        "Severity": severity,
        "Title": f"{cve_id} in test-pkg",
        "_target": f"{image_ref} (test 1.0)",
        "_class": "lang-pkgs",
        "_artifact_name": image_ref,
    }


async def _seed_two_exposed_vuln_workloads_via_writers(store, tenant: str) -> None:
    """Seed two internet-exposed workloads via graph primitives + real vulnerability writer.

    workload-A RUNS_IMAGE img-kev  → CVE_KEV (HIGH, kev=True via record_scan_results)
    workload-B RUNS_IMAGE img-plain → CVE_PLAIN (HIGH, kev=False — not in kev_cve_ids set)

    The image node identity: the workload RUNS_IMAGE an image whose external_id matches the
    ``_artifact_name`` the vulnerability writer keys on — the same join key the integration
    e2e test (test_path2_e2e.py) uses.  We plant the workload + RUNS_IMAGE edge manually
    (mirrors test_kg_query_exposed_vuln._seed), then let record_scan_results upsert the
    image node and VULNERABLE_TO edge (the real writer does both).
    """
    # --- workload A: internet-exposed, will get a KEV CVE ---
    wl_a = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:ecs:us-east-1:111:service/kev-workload",
        properties={"kind": "ecs-service", "is_public": True},
    )
    img_a = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=_IMAGE_KEV,
        properties={"kind": "container-image"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=wl_a,
        dst_entity_id=img_a,
        relationship_type=EdgeType.RUNS_IMAGE.value,
        properties={},
    )

    # --- workload B: internet-exposed, plain (non-KEV) CVE ---
    wl_b = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:ecs:us-east-1:111:service/plain-workload",
        properties={"kind": "ecs-service", "is_public": True},
    )
    img_b = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=_IMAGE_PLAIN,
        properties={"kind": "container-image"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=wl_b,
        dst_entity_id=img_b,
        relationship_type=EdgeType.RUNS_IMAGE.value,
        properties={},
    )

    # --- vulnerability writer: stamp KEV on _CVE_KEV_ID ONLY ---
    # This is the whole point: kev=True must flow through record_scan_results, not through
    # a hand-set properties={"kev": True}.  Under the OLD kev_listed reader the detector
    # reads cve.properties.get("kev_listed", False) — which is always False here (the writer
    # stamps "kev", not "kev_listed") — so AttackPath.kev would be False for both paths.
    trivy_a = TrivyResult(raw_findings=[_trivy_finding(cve_id=_CVE_KEV_ID, image_ref=_IMAGE_KEV)])
    trivy_b = TrivyResult(
        raw_findings=[_trivy_finding(cve_id=_CVE_PLAIN_ID, image_ref=_IMAGE_PLAIN)]
    )
    writer = VulnKgWriter(store, tenant)
    await writer.record_scan_results([trivy_a], kev_cve_ids={_CVE_KEV_ID})
    await writer.record_scan_results([trivy_b], kev_cve_ids=set())  # no KEV ids → kev=False


@pytest.mark.asyncio
async def test_kev_path_outranks_non_kev_through_real_writer() -> None:
    """KEV signal flows writer → node → detector → AttackPath ranking (Task 2 anti-regression).

    This test is RED under the old kg_query.py that reads ``cve.properties.get("kev_listed", False)``
    (the writer stamps ``kev``, so the detector always sees False) and GREEN after the fix that
    reads ``cve.properties.get("kev", False)``.

    Two equal-severity (HIGH) internet-exposed workloads: one's CVE is KEV-listed (via the real
    vulnerability writer), the other is not.  The KEV workload's AttackPath must carry kev=True
    and must outrank the non-KEV path via rank_by_expected_loss.
    """
    t = "kev-writer-regression"
    async with in_memory_semantic_store() as store:
        await _seed_two_exposed_vuln_workloads_via_writers(store, t)

        kq = KgQuery(store, t)
        confirmed = await AttackPathRanker(kq).find_all()

        # Both workloads must produce internet_exposed_vulnerable paths.
        exposed = [p for p in confirmed if p.path_type == "internet_exposed_vulnerable"]
        assert len(exposed) == 2, f"expected 2 exposed-vuln paths, got {len(exposed)}"

        kev_paths = [p for p in exposed if p.kev is True]
        assert len(kev_paths) == 1, (
            "exactly one path must carry kev=True (the one whose CVE was in kev_cve_ids); "
            f"got kev_paths={[p.evidence for p in kev_paths]}"
        )
        assert _CVE_KEV_ID in kev_paths[0].evidence, (
            f"the KEV path must carry {_CVE_KEV_ID!r} as evidence; got {kev_paths[0].evidence}"
        )

        # rank_by_expected_loss must put the KEV path first (KEV lifts leaf_probability floor).
        ranked = await rank_by_expected_loss(confirmed, store, t)
        top_path = ranked[0][0]
        assert top_path.kev is True, (
            "rank_by_expected_loss must place the KEV-listed path first; "
            f"got top={top_path.evidence!r} kev={top_path.kev}"
        )
