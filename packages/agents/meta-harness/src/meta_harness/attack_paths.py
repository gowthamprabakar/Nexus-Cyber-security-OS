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


#: Relative ordering of CVE severity labels, for rolling up "worst CVE" in a grouped path.
_CVE_RANK: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass(frozen=True, slots=True)
class AttackPath:
    """One normalized, ranked attack path — the unit the customer sees.

    A path is ONE structural subject (a workload, a resource, a principal→resource pair) with its
    fan-out evidence rolled up: ``evidence`` is the list of CVEs (vuln paths) or data types (data
    paths) the subject carries, and ``count`` is how many. So a workload with nine CVEs is ONE
    crown-jewel path with ``count=9`` — not nine rows.
    """

    path_type: str
    severity: int
    title: str
    entities: tuple[str, ...]
    evidence: tuple[str, ...] = ()
    count: int = 1


class _Group:
    """Accumulates the detector hits that share one (path_type, subject) into a single path."""

    __slots__ = ("context", "entities", "evidence", "worst")

    def __init__(self) -> None:
        self.entities: set[str] = set()
        self.evidence: list[str] = []  # CVE ids or data types — order-preserving, deduped
        self.worst: str = ""  # worst CVE severity label seen (vuln paths only)
        self.context: dict[str, str] = {}  # descriptive fields constant within the group

    def add(
        self, entities: tuple[str, ...], item: str, *, cve_severity: str = "", **context: str
    ) -> None:
        self.entities.update(entities)
        if item and item not in self.evidence:
            self.evidence.append(item)
        if cve_severity and _CVE_RANK.get(cve_severity, 0) > _CVE_RANK.get(self.worst, 0):
            self.worst = cve_severity
        for key, value in context.items():
            self.context.setdefault(key, value)


def _cve_phrase(grp: _Group) -> str:
    """Human evidence phrase for a vuln path: one CVE, or a rolled-up count + worst severity."""
    n = len(grp.evidence)
    if n == 1:
        return f"{grp.evidence[0]} ({grp.worst})" if grp.worst else grp.evidence[0]
    return f"{n} known CVEs, worst {grp.worst}" if grp.worst else f"{n} known CVEs"


def _types_phrase(grp: _Group) -> str:
    """Human evidence phrase for a data path: the exposed data type(s)."""
    return ", ".join(grp.evidence)


def _title(path_type: str, grp: _Group) -> str:
    if path_type == "crown_jewel":
        dt = grp.context.get("data_type", "")
        return (
            f"Internet-exposed workload runs a vulnerable image ({_cve_phrase(grp)}) "
            f"as a role that can read {dt} data"
        )
    if path_type == "internet_exposed_vulnerable":
        return f"Internet-exposed workload runs an image with {_cve_phrase(grp)}"
    if path_type == "privileged_vulnerable":
        return f"Privileged K8s pod runs an image with {_cve_phrase(grp)}"
    if path_type == "public_secret":
        return f"Public resource exposes a {_types_phrase(grp)} credential"
    if path_type == "public_unencrypted":
        return f"Public unencrypted resource exposes {_types_phrase(grp)} data"
    if path_type == "external_trust":
        return f"Externally-trusted principal can reach {_types_phrase(grp)} data"
    if path_type == "exposed_ai_sensitive_data":
        return f"Internet-exposed AI service reads {_types_phrase(grp)} training data"
    if path_type == "resource_based_data":
        return (
            f"{grp.context.get('principal', '')} has bucket-policy access to "
            f"{_types_phrase(grp)} data"
        )
    return f"Principal has access to public {_types_phrase(grp)} data"  # fine_grained_data


class AttackPathRanker:
    """Runs every self-seeded detector and returns a worst-first ranked attack-path list.

    Each detector hit is folded into its (path_type, structural-subject) group, so the same subject
    with N pieces of evidence (CVEs / data types) collapses to ONE ranked path with ``count=N`` —
    the "top ~10 prioritized" the North Star promises, not one row per CVE.
    """

    def __init__(self, kg: KgQuery) -> None:
        self._kg = kg

    async def find_all(self) -> list[AttackPath]:
        """All attack paths, grouped by subject and ranked worst-first.

        Worst-first = severity desc, then evidence ``count`` desc (a workload with more CVEs
        outranks one with fewer at the same severity), then title for stability.
        """
        groups: dict[tuple[str, tuple[str, ...]], _Group] = {}

        def g(path_type: str, subject: tuple[str, ...]) -> _Group:
            return groups.setdefault((path_type, subject), _Group())

        for h in await self._kg.find_crown_jewel_exposure():
            g("crown_jewel", (h.workload_id, h.role_id, h.resource_id)).add(
                (h.workload_id, h.image_id, h.role_id, h.resource_id),
                h.cve_id,
                data_type=h.data_type,
            )
        for v in await self._kg.find_internet_exposed_vulnerable_workload():
            g("internet_exposed_vulnerable", (v.workload_id, v.image_id)).add(
                (v.workload_id, v.image_id), v.cve_id, cve_severity=v.severity
            )
        for p in await self._kg.find_privileged_vulnerable_workload():
            g("privileged_vulnerable", (p.workload_id, p.image_id)).add(
                (p.workload_id, p.image_id), p.cve_id, cve_severity=p.severity
            )
        for s in await self._kg.find_public_secret_exposure():
            g("public_secret", (s.resource_id,)).add(
                (s.resource_id, s.data_classification_id), s.data_type
            )
        for u in await self._kg.find_public_unencrypted_exposure():
            g("public_unencrypted", (u.resource_id,)).add(
                (u.resource_id, u.data_classification_id), u.data_type
            )
        for e in await self._kg.find_external_trust_exposure():
            g("external_trust", (e.principal_id, e.resource_id)).add(
                (e.principal_id, e.resource_id, e.data_classification_id), e.data_type
            )
        for a in await self._kg.find_exposed_ai_with_sensitive_data():
            g("exposed_ai_sensitive_data", (a.service_id, a.resource_id)).add(
                (a.service_id, a.resource_id, a.data_classification_id), a.data_type
            )
        for rb in await self._kg.find_resource_based_data_exposure():
            g("resource_based_data", (rb.resource_id, rb.principal_arn)).add(
                (rb.resource_id,), rb.data_type, principal=rb.principal_arn
            )
        for f in await self._kg.find_fine_grained_data_exposure():
            g("fine_grained_data", (f.principal_id, f.resource_id)).add(
                (f.principal_id, f.resource_id, f.data_classification_id), f.data_type
            )

        paths = [
            AttackPath(
                path_type=path_type,
                severity=_SEVERITY[path_type],
                title=_title(path_type, grp),
                entities=tuple(sorted(grp.entities)),
                evidence=tuple(grp.evidence),
                count=len(grp.evidence),
            )
            for (path_type, _subject), grp in groups.items()
        ]
        paths.sort(key=lambda p: (-p.severity, -p.count, p.title))
        return paths


__all__ = ["AttackPath", "AttackPathRanker"]
