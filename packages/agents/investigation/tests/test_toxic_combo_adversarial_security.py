"""ADVERSARIAL security tests for the cross-agent toxic-combination detector.

Tests ASSERT the safe behavior (empty result / no false positive). A failing test
is a REAL VULNERABILITY — do not weaken assertions to make them pass.

Attack groups:
  1. TENANT ISOLATION — cross-tenant graph leakage (highest priority)
  2. Missing-leg false positives — each missing edge must silence detection
  3. Wrong-finding-type — non-overprivilege 2004 findings must be ignored
  4. Statement safety — hypothesis statement must not leak resource identifiers
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from investigation.tools.related_findings import RelatedFinding
from investigation.toxic_combination import (
    detect_toxic_combination_hypotheses,
    to_hypothesis,
)
from meta_harness.kg_query import KgQuery, PathEdge, ToxicCombination

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _overpriv_finding(uid: str, principal_arn: str, *, tenant_id: str = "A") -> RelatedFinding:
    """Build a minimal identity 2004 overprivilege RelatedFinding."""
    return RelatedFinding(
        source_agent="identity",
        source_run_id=f"run-{tenant_id}",
        class_uid=2004,
        payload={
            "class_uid": 2004,
            "finding_info": {"uid": uid, "types": ["overprivilege"]},
            "affected_principals": [{"type": "Role", "name": "app", "uid": principal_arn}],
        },
    )


async def _seed_full_toxic_path(store, *, tenant_id: str, principal_arn: str, bucket_arn: str):
    """Seed a COMPLETE toxic path under a single tenant."""
    role_id = await store.upsert_entity(
        tenant_id=tenant_id,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=principal_arn,
        properties={},
    )
    bucket_id = await store.upsert_entity(
        tenant_id=tenant_id,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=bucket_arn,
        properties={},
    )
    data_id = await store.upsert_entity(
        tenant_id=tenant_id,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{bucket_arn}:ssn",
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=tenant_id,
        src_entity_id=role_id,
        dst_entity_id=bucket_id,
        relationship_type=EdgeType.HAS_ACCESS_TO.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=tenant_id,
        src_entity_id=bucket_id,
        dst_entity_id=data_id,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return role_id, bucket_id, data_id


# ===========================================================================
# GROUP 1: TENANT ISOLATION
# ===========================================================================


class TestTenantIsolation:
    """Cross-tenant path reconstruction MUST return [] — every variant."""

    @pytest.mark.asyncio
    async def test_principal_in_a_access_edge_in_a_expose_only_in_b_is_empty_for_a(self):
        """The EXPOSES_DATA edge exists only under tenant B.
        KgQuery(A) must NOT cross the tenant fence to find it → should return [].

        Attack: seed the principal + HAS_ACCESS_TO under tenant A; seed ONLY the
        EXPOSES_DATA edge under tenant B (with the same bucket entity_id reference
        forced to match). The path A→bucket→data exists only across tenants.
        """
        async with in_memory_semantic_store() as store:
            t_a, t_b = "tenant-A", "tenant-B"
            principal_arn = "arn:aws:iam::1:role/split-path"
            bucket_arn = "arn:aws:s3:::cross-bucket"

            # Tenant A: principal + bucket + HAS_ACCESS_TO
            role_a = await store.upsert_entity(
                tenant_id=t_a,
                entity_type=NodeCategory.IDENTITY.value,
                external_id=principal_arn,
                properties={},
            )
            bucket_a = await store.upsert_entity(
                tenant_id=t_a,
                entity_type=NodeCategory.CLOUD_RESOURCE.value,
                external_id=bucket_arn,
                properties={},
            )
            await store.add_relationship(
                tenant_id=t_a,
                src_entity_id=role_a,
                dst_entity_id=bucket_a,
                relationship_type=EdgeType.HAS_ACCESS_TO.value,
                properties={},
            )

            # Tenant B: bucket + data + EXPOSES_DATA (principal + HAS_ACCESS_TO absent)
            bucket_b = await store.upsert_entity(
                tenant_id=t_b,
                entity_type=NodeCategory.CLOUD_RESOURCE.value,
                external_id=bucket_arn,  # same ARN string, different tenant
                properties={},
            )
            data_b = await store.upsert_entity(
                tenant_id=t_b,
                entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                external_id=f"{bucket_arn}:ssn",
                properties={},
            )
            await store.add_relationship(
                tenant_id=t_b,
                src_entity_id=bucket_b,
                dst_entity_id=data_b,
                relationship_type=EdgeType.EXPOSES_DATA.value,
                properties={},
            )

            # Query from tenant A: no complete path exists within A
            hits = await KgQuery(store, t_a).find_public_data_exposure(
                over_permissioned_principal_ids=[role_a]
            )
            assert hits == [], (
                "VULNERABILITY: cross-tenant path found — EXPOSES_DATA leg leaked from tenant B "
                f"to tenant A query. hits={hits}"
            )

    @pytest.mark.asyncio
    async def test_complete_path_only_in_b_returns_empty_for_a(self):
        """A complete toxic path exists under tenant B.
        Querying tenant A (which has NO nodes at all) must return [].

        This checks that an empty principal list results in [] regardless.
        """
        async with in_memory_semantic_store() as store:
            t_a, t_b = "tenant-A", "tenant-B"
            principal_arn = "arn:aws:iam::1:role/only-in-b"
            bucket_arn = "arn:aws:s3:::only-in-b-bucket"

            # Full path exists only under tenant B
            role_b, _, _ = await _seed_full_toxic_path(
                store, tenant_id=t_b, principal_arn=principal_arn, bucket_arn=bucket_arn
            )

            # Tenant A: query with an entity_id that belongs to tenant B
            # The entity_id is a ULID internal to B — passing it under A's KgQuery must return []
            hits = await KgQuery(store, t_a).find_public_data_exposure(
                over_permissioned_principal_ids=[role_b]  # ID from B, queried under A
            )
            assert hits == [], (
                "VULNERABILITY: querying with a tenant-B entity_id under tenant A returned "
                f"a hit, meaning tenant-A's KgQuery walked tenant-B's edges. hits={hits}"
            )

    @pytest.mark.asyncio
    async def test_arn_collision_does_not_cause_cross_tenant_join(self):
        """Same ARN strings appear in BOTH tenants A and B.
        The principal in A and the public bucket in B share the same ARN.
        KgQuery(A).find_public_data_exposure must only return a hit if A has its OWN
        complete path — not by joining through the shared ARN string.

        This is the classic 'shared external_id across tenants' confusion attack.
        """
        async with in_memory_semantic_store() as store:
            t_a, t_b = "tenant-A", "tenant-B"
            shared_principal_arn = "arn:aws:iam::1:role/shared-name"
            bucket_arn = "arn:aws:s3:::shared-bucket"

            # Tenant A: principal only (no HAS_ACCESS_TO, no bucket)
            role_a = await store.upsert_entity(
                tenant_id=t_a,
                entity_type=NodeCategory.IDENTITY.value,
                external_id=shared_principal_arn,
                properties={},
            )

            # Tenant B: full toxic path with the same principal ARN
            await _seed_full_toxic_path(
                store, tenant_id=t_b, principal_arn=shared_principal_arn, bucket_arn=bucket_arn
            )

            # Querying tenant A with role_a (A's entity ID) must return []
            hits = await KgQuery(store, t_a).find_public_data_exposure(
                over_permissioned_principal_ids=[role_a]
            )
            assert hits == [], (
                "VULNERABILITY: ARN collision caused a cross-tenant path — tenant A's principal "
                "joined with tenant B's graph edges via shared ARN. hits={hits}"
            )

    @pytest.mark.asyncio
    async def test_detect_toxic_combination_hypotheses_does_not_correlate_cross_tenant(self):
        """detect_toxic_combination_hypotheses is called with customer_id='A' and an identity
        finding that carries an ARN from tenant B's graph.
        Must return () — even if tenant B has a full toxic path for that ARN.
        """
        async with in_memory_semantic_store() as store:
            t_a, t_b = "tenant-A", "tenant-B"
            principal_arn = "arn:aws:iam::1:role/b-only"
            bucket_arn = "arn:aws:s3:::b-only-bucket"

            # Full toxic path under tenant B
            await _seed_full_toxic_path(
                store, tenant_id=t_b, principal_arn=principal_arn, bucket_arn=bucket_arn
            )

            # Finding that references tenant B's principal ARN but is submitted under customer A
            finding = _overpriv_finding("B-FINDING-001", principal_arn, tenant_id="A")
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store,
                customer_id=t_a,  # querying as tenant A
                related_findings=[finding],
            )
            assert hyps == (), (
                "VULNERABILITY: detect_toxic_combination_hypotheses under customer_id='A' "
                "correlated with tenant B's graph path using a shared principal ARN. "
                f"hyps={hyps}"
            )

    @pytest.mark.asyncio
    async def test_cross_tenant_variant_access_edge_in_a_expose_in_b_via_detect(self):
        """Variant of cross-tenant isolation tested through the full detect function.
        HAS_ACCESS_TO exists only in tenant A, EXPOSES_DATA only in tenant B.
        detect_toxic_combination_hypotheses(customer_id='A') must return ().
        """
        async with in_memory_semantic_store() as store:
            t_a, t_b = "tenant-A", "tenant-B"
            principal_arn = "arn:aws:iam::1:role/split-detect"
            bucket_arn = "arn:aws:s3:::split-bucket"

            # Tenant A: principal + bucket entity + HAS_ACCESS_TO edge (no EXPOSES_DATA)
            role_a = await store.upsert_entity(
                tenant_id=t_a,
                entity_type=NodeCategory.IDENTITY.value,
                external_id=principal_arn,
                properties={},
            )
            bucket_a = await store.upsert_entity(
                tenant_id=t_a,
                entity_type=NodeCategory.CLOUD_RESOURCE.value,
                external_id=bucket_arn,
                properties={},
            )
            await store.add_relationship(
                tenant_id=t_a,
                src_entity_id=role_a,
                dst_entity_id=bucket_a,
                relationship_type=EdgeType.HAS_ACCESS_TO.value,
                properties={},
            )

            # Tenant B: same bucket ARN → EXPOSES_DATA → data node
            bucket_b = await store.upsert_entity(
                tenant_id=t_b,
                entity_type=NodeCategory.CLOUD_RESOURCE.value,
                external_id=bucket_arn,
                properties={},
            )
            data_b = await store.upsert_entity(
                tenant_id=t_b,
                entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                external_id=f"{bucket_arn}:pii",
                properties={},
            )
            await store.add_relationship(
                tenant_id=t_b,
                src_entity_id=bucket_b,
                dst_entity_id=data_b,
                relationship_type=EdgeType.EXPOSES_DATA.value,
                properties={},
            )

            finding = _overpriv_finding("IDENT-001", principal_arn, tenant_id="A")
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store,
                customer_id=t_a,
                related_findings=[finding],
            )
            assert hyps == (), (
                "VULNERABILITY: split-tenant path (HAS_ACCESS_TO in A, EXPOSES_DATA in B) "
                f"produced a hypothesis under tenant A. hyps={hyps}"
            )


# ===========================================================================
# GROUP 2: MISSING-LEG FALSE POSITIVES
# ===========================================================================


class TestMissingLegFalsePositives:
    """Each individually missing edge must prevent the finding from firing."""

    @pytest.mark.asyncio
    async def test_no_has_access_to_edge_despite_public_bucket_and_overprivilege(self):
        """Over-permissioned principal + public bucket (EXPOSES_DATA exists) BUT no
        HAS_ACCESS_TO edge between them. KgQuery must return [].

        The principal is seeded; the bucket has EXPOSES_DATA; but the access edge is absent.
        """
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            principal_arn = "arn:aws:iam::1:role/no-access-edge"
            bucket_arn = "arn:aws:s3:::public-but-unreachable"

            role_id = await store.upsert_entity(
                tenant_id=t,
                entity_type=NodeCategory.IDENTITY.value,
                external_id=principal_arn,
                properties={},
            )
            bucket_id = await store.upsert_entity(
                tenant_id=t,
                entity_type=NodeCategory.CLOUD_RESOURCE.value,
                external_id=bucket_arn,
                properties={},
            )
            data_id = await store.upsert_entity(
                tenant_id=t,
                entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                external_id=f"{bucket_arn}:ssn",
                properties={},
            )
            # NO HAS_ACCESS_TO — only EXPOSES_DATA exists
            await store.add_relationship(
                tenant_id=t,
                src_entity_id=bucket_id,
                dst_entity_id=data_id,
                relationship_type=EdgeType.EXPOSES_DATA.value,
                properties={},
            )

            hits = await KgQuery(store, t).find_public_data_exposure(
                over_permissioned_principal_ids=[role_id]
            )
            assert hits == [], (
                f"FALSE POSITIVE: missing HAS_ACCESS_TO but hit was still returned. hits={hits}"
            )

    @pytest.mark.asyncio
    async def test_private_bucket_contains_data_but_no_exposes_data_edge(self):
        """Principal has HAS_ACCESS_TO a bucket that has a CONTAINS edge to data
        (simulating a private bucket with data), but NO EXPOSES_DATA edge.
        The detector must NOT follow CONTAINS — only EXPOSES_DATA proves public exposure.
        """
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            principal_arn = "arn:aws:iam::1:role/contains-only"
            bucket_arn = "arn:aws:s3:::private-bucket"

            role_id = await store.upsert_entity(
                tenant_id=t,
                entity_type=NodeCategory.IDENTITY.value,
                external_id=principal_arn,
                properties={},
            )
            bucket_id = await store.upsert_entity(
                tenant_id=t,
                entity_type=NodeCategory.CLOUD_RESOURCE.value,
                external_id=bucket_arn,
                properties={},
            )
            data_id = await store.upsert_entity(
                tenant_id=t,
                entity_type=NodeCategory.DATA_CLASSIFICATION.value,
                external_id=f"{bucket_arn}:ssn",
                properties={},
            )
            # HAS_ACCESS_TO exists
            await store.add_relationship(
                tenant_id=t,
                src_entity_id=role_id,
                dst_entity_id=bucket_id,
                relationship_type=EdgeType.HAS_ACCESS_TO.value,
                properties={},
            )
            # CONTAINS (private, not public) instead of EXPOSES_DATA
            await store.add_relationship(
                tenant_id=t,
                src_entity_id=bucket_id,
                dst_entity_id=data_id,
                relationship_type=EdgeType.CONTAINS.value,
                properties={},
            )

            hits = await KgQuery(store, t).find_public_data_exposure(
                over_permissioned_principal_ids=[role_id]
            )
            assert hits == [], (
                "FALSE POSITIVE: CONTAINS edge was followed as if it were EXPOSES_DATA. "
                f"hits={hits}"
            )

    @pytest.mark.asyncio
    async def test_public_bucket_sensitive_data_but_principal_not_in_any_overprivilege_finding(
        self,
    ):
        """A bucket IS public (EXPOSES_DATA seeded) and the principal HAS_ACCESS_TO it,
        but the principal does NOT appear in any 'overprivilege' finding — only in a
        'dormant' finding. detect_toxic_combination_hypotheses must return ().

        This tests that detection requires BOTH legs: graph path AND overprivilege signal.
        """
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            principal_arn = "arn:aws:iam::1:role/dormant-not-overpriv"
            bucket_arn = "arn:aws:s3:::public-with-data"

            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=principal_arn, bucket_arn=bucket_arn
            )

            # Finding exists but type is NOT overprivilege
            dormant_finding = RelatedFinding(
                source_agent="identity",
                source_run_id="run-1",
                class_uid=2004,
                payload={
                    "finding_info": {"uid": "DORMANT-001", "types": ["dormant"]},
                    "affected_principals": [{"uid": principal_arn}],
                },
            )
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store,
                customer_id=t,
                related_findings=[dormant_finding],
            )
            assert hyps == (), (
                "FALSE POSITIVE: full graph path exists but non-overprivilege finding "
                f"triggered a hypothesis. hyps={hyps}"
            )

    @pytest.mark.asyncio
    async def test_no_nodes_seeded_at_all_for_tenant(self):
        """Empty graph for the tenant — must return [] not raise."""
        async with in_memory_semantic_store() as store:
            hits = await KgQuery(store, "fresh-tenant").find_public_data_exposure(
                over_permissioned_principal_ids=["nonexistent-id"]
            )
            assert hits == []

    @pytest.mark.asyncio
    async def test_empty_principal_list_returns_empty(self):
        """Passing an empty principal list to find_public_data_exposure must return []."""
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            principal_arn = "arn:aws:iam::1:role/app"
            bucket_arn = "arn:aws:s3:::bucket"
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=principal_arn, bucket_arn=bucket_arn
            )
            hits = await KgQuery(store, t).find_public_data_exposure(
                over_permissioned_principal_ids=[]
            )
            assert hits == [], f"Empty principal list should return [], got {hits}"


# ===========================================================================
# GROUP 3: WRONG-FINDING-TYPE
# ===========================================================================


class TestWrongFindingType:
    """Findings that are not overprivilege-typed 2004s must never seed the detector."""

    @pytest.mark.asyncio
    async def test_dormant_finding_type_does_not_trigger_hypothesis(self):
        """2004 finding with types=['dormant'] + full toxic path → no hypothesis."""
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            arn = "arn:aws:iam::1:role/dormant"
            bucket_arn = "arn:aws:s3:::dormant-bucket"
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=arn, bucket_arn=bucket_arn
            )

            rf = RelatedFinding(
                source_agent="identity",
                source_run_id="r",
                class_uid=2004,
                payload={
                    "finding_info": {"uid": "D-001", "types": ["dormant"]},
                    "affected_principals": [{"uid": arn}],
                },
            )
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store, customer_id=t, related_findings=[rf]
            )
            assert hyps == (), f"dormant finding should not trigger hypothesis, got {hyps}"

    @pytest.mark.asyncio
    async def test_mfa_gap_finding_type_does_not_trigger_hypothesis(self):
        """2004 finding with types=['mfa_gap'] + full toxic path → no hypothesis."""
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            arn = "arn:aws:iam::1:role/mfa-gap"
            bucket_arn = "arn:aws:s3:::mfa-bucket"
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=arn, bucket_arn=bucket_arn
            )

            rf = RelatedFinding(
                source_agent="identity",
                source_run_id="r",
                class_uid=2004,
                payload={
                    "finding_info": {"uid": "MFA-001", "types": ["mfa_gap"]},
                    "affected_principals": [{"uid": arn}],
                },
            )
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store, customer_id=t, related_findings=[rf]
            )
            assert hyps == (), f"mfa_gap finding should not trigger hypothesis, got {hyps}"

    @pytest.mark.asyncio
    async def test_wrong_class_uid_2003_not_seeded(self):
        """A class 2003 (posture, not identity) finding is NOT a 2004 → silently ignored."""
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            arn = "arn:aws:iam::1:role/wrong-class"
            bucket_arn = "arn:aws:s3:::wrong-class-bucket"
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=arn, bucket_arn=bucket_arn
            )

            rf = RelatedFinding(
                source_agent="cloud_posture",
                source_run_id="r",
                class_uid=2003,  # Not 2004
                payload={
                    "finding_info": {"uid": "CP-001", "types": ["overprivilege"]},
                    "affected_principals": [{"uid": arn}],
                },
            )
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store, customer_id=t, related_findings=[rf]
            )
            assert hyps == (), (
                f"class_uid=2003 must not trigger hypothesis even with overprivilege types. got {hyps}"
            )

    @pytest.mark.asyncio
    async def test_mixed_findings_only_overpriv_one_fires(self):
        """Findings list contains a dormant + an mfa_gap + an overprivilege finding.
        Only the overprivilege one should trigger, for the correct principal only.
        """
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            overpriv_arn = "arn:aws:iam::1:role/overpriv"
            dormant_arn = "arn:aws:iam::1:role/dormant-mixed"
            bucket_arn_overpriv = "arn:aws:s3:::overpriv-bucket"
            bucket_arn_dormant = "arn:aws:s3:::dormant-bucket-mixed"

            # Both principals have complete toxic paths in graph
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=overpriv_arn, bucket_arn=bucket_arn_overpriv
            )
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=dormant_arn, bucket_arn=bucket_arn_dormant
            )

            findings = [
                RelatedFinding(
                    source_agent="identity",
                    source_run_id="r",
                    class_uid=2004,
                    payload={
                        "finding_info": {"uid": "DORM-MIXED-001", "types": ["dormant"]},
                        "affected_principals": [{"uid": dormant_arn}],
                    },
                ),
                RelatedFinding(
                    source_agent="identity",
                    source_run_id="r",
                    class_uid=2004,
                    payload={
                        "finding_info": {"uid": "OVERPRIV-MIXED-001", "types": ["overprivilege"]},
                        "affected_principals": [{"uid": overpriv_arn}],
                    },
                ),
                RelatedFinding(
                    source_agent="identity",
                    source_run_id="r",
                    class_uid=2004,
                    payload={
                        "finding_info": {"uid": "MFA-MIXED-001", "types": ["mfa_gap"]},
                        "affected_principals": [{"uid": dormant_arn}],
                    },
                ),
            ]
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store, customer_id=t, related_findings=findings
            )
            # Exactly ONE hypothesis for overpriv_arn
            assert len(hyps) == 1, (
                f"Expected exactly 1 hypothesis (overpriv only), got {len(hyps)}. hyps={hyps}"
            )
            assert hyps[0].evidence_refs == ("finding:OVERPRIV-MIXED-001",), (
                f"Hypothesis should cite the overprivilege finding only, got {hyps[0].evidence_refs}"
            )

    @pytest.mark.asyncio
    async def test_finding_with_empty_types_list_not_seeded(self):
        """Finding with types=[] (no overprivilege marker) + full path → no hypothesis."""
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            arn = "arn:aws:iam::1:role/empty-types"
            bucket_arn = "arn:aws:s3:::empty-types-bucket"
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=arn, bucket_arn=bucket_arn
            )

            rf = RelatedFinding(
                source_agent="identity",
                source_run_id="r",
                class_uid=2004,
                payload={
                    "finding_info": {"uid": "EMPTY-001", "types": []},
                    "affected_principals": [{"uid": arn}],
                },
            )
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store, customer_id=t, related_findings=[rf]
            )
            assert hyps == (), f"Empty types list should not seed detector. got {hyps}"

    @pytest.mark.asyncio
    async def test_finding_with_no_finding_info_key_not_seeded(self):
        """Finding with missing finding_info entirely → not seeded → no hypothesis."""
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            arn = "arn:aws:iam::1:role/no-info"
            bucket_arn = "arn:aws:s3:::no-info-bucket"
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=arn, bucket_arn=bucket_arn
            )

            rf = RelatedFinding(
                source_agent="identity",
                source_run_id="r",
                class_uid=2004,
                payload={
                    # no finding_info key at all
                    "affected_principals": [{"uid": arn}],
                },
            )
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store, customer_id=t, related_findings=[rf]
            )
            assert hyps == (), f"Missing finding_info should yield no hypothesis. got {hyps}"


# ===========================================================================
# GROUP 4: STATEMENT SAFETY — no resource identifiers / PII in hypothesis text
# ===========================================================================


class TestStatementSafety:
    """Emitted hypothesis.statement must be GENERIC categorical text.
    Leaking bucket ARNs, principal ARNs, or data classification external IDs
    into the statement is a finding-quality data-in-finding PII leak.
    """

    _SENSITIVE_STRINGS: ClassVar[list[str]] = [
        "arn:aws:",
        "arn:azure:",
        "s3://",
        "arn:aws:s3:::",
        "arn:aws:iam::",
        ".amazonaws.com",
        "ssn",  # raw data-type label
        "pii",
        "bucket-",  # any fragment that looks like a resource name fragment
    ]

    def _assert_no_resource_ids_in_statement(self, statement: str, *, context: str) -> None:
        lower = statement.lower()
        for fragment in self._SENSITIVE_STRINGS:
            assert fragment.lower() not in lower, (
                f"FINDING: hypothesis statement leaks resource identifier fragment "
                f"'{fragment}' in context '{context}'. statement={statement!r}"
            )

    def test_to_hypothesis_statement_is_generic_text(self):
        """to_hypothesis() with realistic-looking IDs must produce a generic statement."""
        combo = ToxicCombination(
            principal_id="01JXXXXXXXXXXXXXXXXXXXX",
            resource_id="01JYYYYYYYYYYYYYYYYY",
            data_classification_id="01JZZZZZZZZZZZZZZZZZ",
            path=(
                PathEdge(
                    "01JXXXXXXXXXXXXXXXXXXXX",
                    "01JYYYYYYYYYYYYYYYYY",
                    EdgeType.HAS_ACCESS_TO.value,
                ),
                PathEdge(
                    "01JYYYYYYYYYYYYYYYYY",
                    "01JZZZZZZZZZZZZZZZZZ",
                    EdgeType.EXPOSES_DATA.value,
                ),
            ),
        )
        hyp = to_hypothesis(combo, evidence_refs=("finding:uid-abc",))
        self._assert_no_resource_ids_in_statement(
            hyp.statement, context="to_hypothesis with ULID IDs"
        )

    def test_to_hypothesis_statement_when_arn_slips_in_as_principal_id(self):
        """Worst-case: an ARN was accidentally stored as the principal_id ULID slot.
        The statement must STILL be generic — it should never interpolate these fields.
        """
        combo = ToxicCombination(
            principal_id="arn:aws:iam::123456789:role/over-admin",
            resource_id="arn:aws:s3:::acme-payroll-pii",
            data_classification_id="arn:aws:s3:::acme-payroll-pii:ssn",
            path=(
                PathEdge(
                    "arn:aws:iam::123456789:role/over-admin",
                    "arn:aws:s3:::acme-payroll-pii",
                    EdgeType.HAS_ACCESS_TO.value,
                ),
                PathEdge(
                    "arn:aws:s3:::acme-payroll-pii",
                    "arn:aws:s3:::acme-payroll-pii:ssn",
                    EdgeType.EXPOSES_DATA.value,
                ),
            ),
        )
        hyp = to_hypothesis(combo, evidence_refs=("finding:DSPM-001",))
        self._assert_no_resource_ids_in_statement(
            hyp.statement, context="to_hypothesis with ARN as IDs"
        )

    @pytest.mark.asyncio
    async def test_detect_toxic_combination_hypotheses_statement_is_generic(self):
        """Full end-to-end: detect+write produces a generic statement, no ARN fragments."""
        async with in_memory_semantic_store() as store:
            t = "tenant-A"
            principal_arn = "arn:aws:iam::999:role/super-admin"
            bucket_arn = "arn:aws:s3:::acme-ssn-records"
            await _seed_full_toxic_path(
                store, tenant_id=t, principal_arn=principal_arn, bucket_arn=bucket_arn
            )
            finding = _overpriv_finding("IDENT-STMT-001", principal_arn)
            hyps = await detect_toxic_combination_hypotheses(
                semantic_store=store, customer_id=t, related_findings=[finding]
            )
            assert len(hyps) == 1, f"Expected 1 hypothesis for statement check, got {hyps}"
            self._assert_no_resource_ids_in_statement(
                hyps[0].statement, context="detect_toxic_combination_hypotheses e2e"
            )
