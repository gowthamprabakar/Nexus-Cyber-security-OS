"""The north-star surface — one ranked list of a tenant's real attack paths.

Tonight's seven `KgQuery.find_*` detectors each answer one archetype. A customer doesn't want
seven lists; they want *their top attack paths, prioritized*. :class:`AttackPathRanker` runs
the self-seeded detectors over the fleet graph, normalizes every hit into a uniform
:class:`AttackPath` (type + severity + human title + the entities involved), and returns them
ranked worst-first. This is the "connect an account → see your top ~10 real attack paths"
deliverable — read-only, tenant-scoped, built entirely on the verified detectors.

Severity is the product judgment — what a security team triages first:

- ``crown_jewel`` (95): exposed + vulnerable + privileged + sensitive on one workload.
- ``public_secret`` (90): a publicly-readable credential — instant, no exploitation needed.
- ``internet_exposed_vulnerable`` (80): exposed workload + a known CVE.
- ``public_unencrypted`` (75): public sensitive data, not even encrypted.
- ``external_trust`` (70): a foreign account can assume a role that reaches sensitive data.
- ``fine_grained_data`` (60): a principal (incl. admins) with access to public sensitive data.

``find_public_data_exposure`` (path 1, admin-seeded) is intentionally not run here: its hits are
a subset of ``find_fine_grained_data_exposure`` (self-seeded over every HAS_ACCESS_TO principal),
so running both would double-count.
"""

from __future__ import annotations

from dataclasses import dataclass

from meta_harness.kg_query import KgQuery

# path_type → severity (the triage-order product judgment).
_SEVERITY: dict[str, int] = {
    "crown_jewel": 95,
    "public_secret": 90,
    "internet_exposed_vulnerable": 80,
    "privileged_vulnerable": 78,
    "public_unencrypted": 75,
    "external_trust": 70,
    "exposed_ai_sensitive_data": 68,
    "resource_based_data": 62,
    "fine_grained_data": 60,
}


@dataclass(frozen=True, slots=True)
class AttackPath:
    """One normalized, ranked attack path — the unit the customer sees."""

    path_type: str
    severity: int
    title: str
    entities: tuple[str, ...]


class AttackPathRanker:
    """Runs every self-seeded detector and returns a worst-first ranked attack-path list."""

    def __init__(self, kg: KgQuery) -> None:
        self._kg = kg

    async def find_all(self) -> list[AttackPath]:
        """All attack paths across archetypes, ranked by severity (desc), then title."""
        paths: list[AttackPath] = []

        for h in await self._kg.find_crown_jewel_exposure():
            paths.append(
                self._make(
                    "crown_jewel",
                    f"Internet-exposed workload runs vulnerable image ({h.cve_id}) as a role "
                    f"that can read {h.data_type} data",
                    (h.workload_id, h.image_id, h.role_id, h.resource_id),
                )
            )
        for s in await self._kg.find_public_secret_exposure():
            paths.append(
                self._make(
                    "public_secret",
                    f"Public resource exposes a {s.data_type} credential",
                    (s.resource_id, s.data_classification_id),
                )
            )
        for v in await self._kg.find_internet_exposed_vulnerable_workload():
            paths.append(
                self._make(
                    "internet_exposed_vulnerable",
                    f"Internet-exposed workload runs an image with {v.cve_id} ({v.severity})",
                    (v.workload_id, v.image_id),
                )
            )
        for p in await self._kg.find_privileged_vulnerable_workload():
            paths.append(
                self._make(
                    "privileged_vulnerable",
                    f"Privileged K8s pod runs an image with {p.cve_id} ({p.severity})",
                    (p.workload_id, p.image_id),
                )
            )
        for u in await self._kg.find_public_unencrypted_exposure():
            paths.append(
                self._make(
                    "public_unencrypted",
                    f"Public unencrypted resource exposes {u.data_type} data",
                    (u.resource_id, u.data_classification_id),
                )
            )
        for e in await self._kg.find_external_trust_exposure():
            paths.append(
                self._make(
                    "external_trust",
                    f"Externally-trusted principal can reach {e.data_type} data",
                    (e.principal_id, e.resource_id),
                )
            )
        for a in await self._kg.find_exposed_ai_with_sensitive_data():
            paths.append(
                self._make(
                    "exposed_ai_sensitive_data",
                    f"Internet-exposed AI service reads {a.data_type} training data",
                    (a.service_id, a.resource_id),
                )
            )
        for rb in await self._kg.find_resource_based_data_exposure():
            paths.append(
                self._make(
                    "resource_based_data",
                    f"{rb.principal_arn} has bucket-policy access to {rb.data_type} data",
                    (rb.resource_id,),
                )
            )
        for f in await self._kg.find_fine_grained_data_exposure():
            paths.append(
                self._make(
                    "fine_grained_data",
                    f"Principal has access to public {f.data_type} data",
                    (f.principal_id, f.resource_id),
                )
            )

        paths.sort(key=lambda p: (-p.severity, p.title))
        return paths

    def _make(self, path_type: str, title: str, entities: tuple[str, ...]) -> AttackPath:
        return AttackPath(
            path_type=path_type,
            severity=_SEVERITY[path_type],
            title=title,
            entities=entities,
        )


__all__ = ["AttackPath", "AttackPathRanker"]
