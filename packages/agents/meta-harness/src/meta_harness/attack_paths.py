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

Two layers of de-duplication keep the list to "top ~10 prioritized", not raw detector hits:
1. **Grouping** — one structural subject with N pieces of evidence (CVEs / data types) collapses
   to ONE path with ``count=N`` (a workload with nine CVEs is one crown jewel, not nine rows).
2. **Subsumption** — a crown jewel is the most complete framing of its workload, so it folds in the
   constituent legs that would otherwise surface for the SAME subject (that workload's own
   internet-exposed-vulnerable path, and its role's fine-grained access to the same data).
"""

from __future__ import annotations

from dataclasses import dataclass

from meta_harness.kg_query import KgQuery

# path_type → severity (the triage-order product judgment).
_SEVERITY: dict[str, int] = {
    "crown_jewel": 95,
    "leaked_credential": 92,
    "public_secret": 90,
    "runtime_exploit_vulnerable": 88,
    "malicious_destination": 85,
    "exposed_database": 84,
    "lateral_movement": 82,
    "internet_exposed_vulnerable": 80,
    "internet_exposed_host_vulnerable": 79,
    "privileged_vulnerable": 78,
    "rbac_privilege_escalation": 76,
    "public_unencrypted": 75,
    "kms_key_access": 74,
    "escalation_method_to_data": 74,
    "exposed_kms_key": 72,
    "external_trust": 70,
    "exposed_ai_sensitive_data": 68,
    "privilege_escalation": 66,
    "resource_based_data": 62,
    "fine_grained_data": 60,
    "iac_misconfig_deployed": 58,
    "cicd_compromise": 64,
    "stored_secret_to_data": 88,
    "k8s_escape_to_cloud_data": 82,
    "rbac_escalation_to_cloud_data": 84,
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

    ``kev`` and ``epss`` surface the worst-CVE exploitability signal for CVE-bearing paths:
    ``kev=True`` if ANY CVE on the path is CISA KEV-listed; ``epss`` is the maximum EPSS score
    across all CVEs on the path. Non-CVE paths keep the defaults (kev=False, epss=None).
    """

    path_type: str
    severity: int
    title: str
    entities: tuple[str, ...]
    evidence: tuple[str, ...] = ()
    count: int = 1
    sink_id: str = ""  # v0.5: the data-classification this path reaches (for noisy-OR grouping)
    kev: bool = False  # True if any CVE on this path is CISA KEV-listed
    epss: float | None = None  # max EPSS score across all CVEs on this path


class _Group:
    """Accumulates the detector hits that share one (path_type, subject) into a single path."""

    __slots__ = ("context", "entities", "evidence", "kev", "max_epss", "sink", "worst")

    def __init__(self) -> None:
        self.entities: set[str] = set()
        self.evidence: list[str] = []  # CVE ids or data types — order-preserving, deduped
        self.worst: str = ""  # worst CVE severity label seen (vuln paths only)
        self.context: dict[str, str] = {}  # descriptive fields constant within the group
        self.sink: str = ""
        # Exploitability rollup: kev=True if ANY CVE on this path is CISA KEV-listed;
        # max_epss=max EPSS score seen (None means no CVE on this path had an EPSS value).
        self.kev: bool = False
        self.max_epss: float | None = None

    def add(
        self,
        entities: tuple[str, ...],
        item: str,
        *,
        cve_severity: str = "",
        cve_kev: bool = False,
        cve_epss: float | None = None,
        sink: str = "",
        **context: str,
    ) -> None:
        self.entities.update(entities)
        if item and item not in self.evidence:
            self.evidence.append(item)
        if cve_severity and _CVE_RANK.get(cve_severity, 0) > _CVE_RANK.get(self.worst, 0):
            self.worst = cve_severity
        if cve_kev:
            self.kev = True
        if cve_epss is not None:
            self.max_epss = max(self.max_epss, cve_epss) if self.max_epss is not None else cve_epss
        if sink and not self.sink:
            self.sink = sink
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
    if path_type == "internet_exposed_host_vulnerable":
        return (
            f"Internet-exposed host (EC2/VM) has an OS-package vulnerability ({_cve_phrase(grp)})"
        )
    if path_type == "privileged_vulnerable":
        return f"Privileged K8s pod runs an image with {_cve_phrase(grp)}"
    if path_type == "runtime_exploit_vulnerable":
        return f"Active runtime detection on a workload running a vulnerable image ({_cve_phrase(grp)})"
    if path_type == "kms_key_access":
        dt = grp.context.get("data_type", "") or _types_phrase(grp)
        return (
            f"A principal can use a KMS key that protects {dt or 'sensitive'} data (decrypt access)"
        )
    if path_type == "exposed_kms_key":
        return "KMS key policy is internet-open (the encryption boundary is exposed)"
    if path_type == "rbac_privilege_escalation":
        role = grp.context.get("role_name", "")
        return f"K8s ServiceAccount is bound to a cluster-admin RBAC role ({role}) — full cluster control"
    if path_type == "exposed_database":
        return f"Internet-facing managed database ({_types_phrase(grp)}) is publicly accessible"
    if path_type == "lateral_movement":
        return (
            f"Public foothold has an observed network flow to an internal vulnerable host "
            f"({_cve_phrase(grp)}) — lateral movement"
        )
    if path_type == "malicious_destination":
        return f"Resource is communicating with a known-malicious IP ({_types_phrase(grp)})"
    if path_type == "leaked_credential":
        return f"A live cloud credential is committed in source code and can reach {_types_phrase(grp)} data"
    if path_type == "public_secret":
        return f"Public resource exposes a {_types_phrase(grp)} credential"
    if path_type == "public_unencrypted":
        return f"Public unencrypted resource exposes {_types_phrase(grp)} data"
    if path_type == "external_trust":
        return f"Externally-trusted principal can reach {_types_phrase(grp)} data"
    if path_type == "privilege_escalation":
        return (
            f"Principal can assume a role to reach {_types_phrase(grp)} data (privilege escalation)"
        )
    if path_type == "exposed_ai_sensitive_data":
        return f"Internet-exposed AI service reads {_types_phrase(grp)} training data"
    if path_type == "resource_based_data":
        return (
            f"{grp.context.get('principal', '')} has bucket-policy access to "
            f"{_types_phrase(grp)} data"
        )
    if path_type == "iac_misconfig_deployed":
        return f"Live resource deployed from misconfigured infrastructure-as-code ({_types_phrase(grp)})"
    if path_type == "cicd_compromise":
        return "Production resource deployed from a repo holding a leaked credential (poisonable pipeline)"
    if path_type == "stored_secret_to_data":
        return (
            f"Running workload embeds a credential whose owner can reach "
            f"{_types_phrase(grp)} data (hard-coded secret blast radius)"
        )
    if path_type == "k8s_escape_to_cloud_data":
        dt = grp.context.get("data_type", "") or _types_phrase(grp)
        return (
            f"A privileged pod can escape to its cloud IAM role and reach {dt or 'sensitive'} data"
        )
    if path_type == "escalation_method_to_data":
        method = grp.context.get("method", "")
        dt = grp.context.get("data_type", "") or _types_phrase(grp)
        method_clause = f" (via {method})" if method else ""
        return (
            f"A principal can escalate to admin{method_clause} and reach {dt or 'sensitive'} data"
        )
    if path_type == "rbac_escalation_to_cloud_data":
        role = grp.context.get("role_name", "")
        dt = grp.context.get("data_type", "") or _types_phrase(grp)
        return (
            f"K8s ServiceAccount is bound to a cluster-admin RBAC role ({role}) "
            f"AND its IRSA cloud role can reach {dt or 'sensitive'} data — "
            f"full cluster control plus cloud data breach"
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

        # A crown jewel is the most complete framing of its workload, so it SUBSUMES the
        # constituent legs that would otherwise also surface for the SAME subject: the workload's
        # own internet-exposed-vulnerable path, and the fine-grained access of its role to the same
        # data. Those are folded into the crown jewel, not shown as separate rows (no double-count).
        subsumed_workloads: set[str] = set()
        subsumed_access: set[tuple[str, str]] = set()
        # An externally-trusted principal's access to data is the more complete framing, so it
        # SUBSUMES the same (principal, resource) surfacing again as a plain fine-grained grant —
        # otherwise the partner shows as both "External trust" and "Over-permissioned access".
        external_access: set[tuple[str, str]] = set()
        # rbac_escalation_to_cloud_data (deeper combo) subsumed SA ids — a SA showing as the
        # deep combo must NOT also appear as bare rbac_privilege_escalation.
        subsumed_rbac_subjects: set[str] = set()
        for h in await self._kg.find_crown_jewel_exposure():
            g("crown_jewel", (h.workload_id, h.role_id, h.resource_id)).add(
                (h.workload_id, h.image_id, h.role_id, h.resource_id),
                h.cve_id,
                cve_severity=h.severity,
                cve_kev=h.kev_listed,
                cve_epss=h.epss_score,
                data_type=h.data_type,
                sink=h.data_classification_id,
            )
            subsumed_workloads.add(h.workload_id)
            subsumed_access.add((h.role_id, h.resource_id))

        for v in await self._kg.find_internet_exposed_vulnerable_workload():
            if v.workload_id in subsumed_workloads:
                continue  # subsumed by the crown jewel for this workload
            g("internet_exposed_vulnerable", (v.workload_id, v.image_id)).add(
                (v.workload_id, v.image_id),
                v.cve_id,
                cve_severity=v.severity,
                cve_kev=v.kev_listed,
                cve_epss=v.epss_score,
            )
        for p in await self._kg.find_privileged_vulnerable_workload():
            g("privileged_vulnerable", (p.workload_id, p.image_id)).add(
                (p.workload_id, p.image_id),
                p.cve_id,
                cve_severity=p.severity,
                cve_kev=p.kev_listed,
                cve_epss=p.epss_score,
            )
        for hv in await self._kg.find_internet_exposed_host_vulnerable():
            g("internet_exposed_host_vulnerable", (hv.host_id,)).add(
                (hv.host_id,),
                hv.cve_id,
                cve_severity=hv.severity,
                cve_kev=hv.kev_listed,
                cve_epss=hv.epss_score,
            )
        for s in await self._kg.find_public_secret_exposure():
            g("public_secret", (s.resource_id,)).add(
                (s.resource_id, s.data_classification_id),
                s.data_type,
                sink=s.data_classification_id,
            )
        for u in await self._kg.find_public_unencrypted_exposure():
            g("public_unencrypted", (u.resource_id,)).add(
                (u.resource_id, u.data_classification_id),
                u.data_type,
                sink=u.data_classification_id,
            )
        for e in await self._kg.find_external_trust_exposure():
            g("external_trust", (e.principal_id, e.resource_id)).add(
                (e.principal_id, e.resource_id, e.data_classification_id),
                e.data_type,
                sink=e.data_classification_id,
            )
            external_access.add((e.principal_id, e.resource_id))
        for a in await self._kg.find_exposed_ai_with_sensitive_data():
            g("exposed_ai_sensitive_data", (a.service_id, a.resource_id)).add(
                (a.service_id, a.resource_id, a.data_classification_id),
                a.data_type,
                sink=a.data_classification_id,
            )
        for re_ in await self._kg.find_runtime_exploit_on_vulnerable_workload():
            g("runtime_exploit_vulnerable", (re_.host_id,)).add(
                (re_.host_id, re_.image_id),
                re_.cve_id,
                cve_severity=re_.severity,
                cve_kev=re_.kev_listed,
                cve_epss=re_.epss_score,
            )
        for ek in await self._kg.find_exposed_kms_key():
            g("exposed_kms_key", (ek.resource_id,)).add((ek.resource_id,), "kms-key")
        for rc in await self._kg.find_rbac_escalation_to_cloud_data():
            g(
                "rbac_escalation_to_cloud_data",
                (rc.subject_id, rc.cloud_role_id, rc.resource_id),
            ).add(
                (
                    rc.subject_id,
                    rc.admin_role_id,
                    rc.cloud_role_id,
                    rc.resource_id,
                    rc.data_classification_id,
                ),
                rc.data_type,
                role_name=rc.role_name,
                data_type=rc.data_type,
                sink=rc.data_classification_id,
            )
            subsumed_rbac_subjects.add(rc.subject_id)
        for rp in await self._kg.find_rbac_privilege_escalation():
            if rp.subject_id in subsumed_rbac_subjects:
                continue  # subsumed by the deeper rbac_escalation_to_cloud_data combo
            g("rbac_privilege_escalation", (rp.subject_id,)).add(
                (rp.subject_id, rp.role_id), rp.subject_name, role_name=rp.role_name
            )
        for ed in await self._kg.find_exposed_database():
            g("exposed_database", (ed.resource_id,)).add((ed.resource_id,), ed.engine or "database")
        for md in await self._kg.find_resource_contacting_malicious_ip():
            g("malicious_destination", (md.resource_id,)).add(
                (md.resource_id, md.destination_id), md.indicator_value
            )
        for lm in await self._kg.find_lateral_movement_to_vulnerable_host():
            g("lateral_movement", (lm.foothold_id, lm.target_id)).add(
                (lm.foothold_id, lm.target_id),
                lm.cve_id,
                cve_severity=lm.severity,
                cve_kev=lm.kev_listed,
                cve_epss=lm.epss_score,
            )
        for lc in await self._kg.find_leaked_credential_to_data():
            g("leaked_credential", (lc.principal_id, lc.resource_id)).add(
                (
                    lc.principal_id,
                    lc.credential_id,
                    lc.repo_id,
                    lc.resource_id,
                    lc.data_classification_id,
                ),
                lc.data_type,
                sink=lc.data_classification_id,
            )
        for pe in await self._kg.find_privilege_escalation_to_data():
            g("privilege_escalation", (pe.principal_id, pe.resource_id)).add(
                (pe.principal_id, pe.role_id, pe.resource_id, pe.data_classification_id),
                pe.data_type,
                sink=pe.data_classification_id,
            )
        for rb in await self._kg.find_resource_based_data_exposure():
            g("resource_based_data", (rb.resource_id, rb.principal_arn)).add(
                (rb.resource_id,),
                rb.data_type,
                principal=rb.principal_arn,
                sink=rb.data_classification_id,
            )
        # NEX-202a: a principal reaching a KMS key that protects data is the more specific
        # `kms_key_access` — subsume its fine-grained access leg so it is not double-reported.
        kms_access: set[tuple[str, str]] = set()
        for ka in await self._kg.find_kms_key_access():
            g("kms_key_access", (ka.principal_id, ka.kms_key_id)).add(
                (ka.principal_id, ka.kms_key_id, ka.data_classification_id),
                ka.data_type,
                sink=ka.data_classification_id,
            )
            kms_access.add((ka.principal_id, ka.kms_key_id))
        for f in await self._kg.find_fine_grained_data_exposure():
            if (f.principal_id, f.resource_id) in subsumed_access:
                continue  # this role→data access is the crown jewel's own access leg
            if (f.principal_id, f.resource_id) in external_access:
                continue  # already reported as the (more complete) external-trust path
            if (f.principal_id, f.resource_id) in kms_access:
                continue  # the more specific kms_key_access path already reports it
            g("fine_grained_data", (f.principal_id, f.resource_id)).add(
                (f.principal_id, f.resource_id, f.data_classification_id),
                f.data_type,
                sink=f.data_classification_id,
            )
        for ic in await self._kg.find_resource_from_misconfigured_iac():
            g("iac_misconfig_deployed", (ic.resource_id,)).add(
                (ic.resource_id, ic.artifact_id, ic.repo_id), ic.artifact_ref
            )
        for cc in await self._kg.find_cicd_compromise():
            g("cicd_compromise", (cc.resource_id,)).add(
                (cc.resource_id, cc.repo_id), "poisonable-pipeline"
            )
        for ss in await self._kg.find_stored_secret_to_data():
            g("stored_secret_to_data", (ss.workload_id, ss.principal_id, ss.resource_id)).add(
                (
                    ss.workload_id,
                    ss.secret_id,
                    ss.principal_id,
                    ss.resource_id,
                    ss.data_classification_id,
                ),
                ss.data_type,
                sink=ss.data_classification_id,
            )
        for ke in await self._kg.find_k8s_escape_to_cloud_data():
            g("k8s_escape_to_cloud_data", (ke.pod_id, ke.role_id, ke.resource_id)).add(
                (
                    ke.pod_id,
                    ke.service_account_id,
                    ke.role_id,
                    ke.resource_id,
                    ke.data_classification_id,
                ),
                ke.data_type,
                data_type=ke.data_type,
                sink=ke.data_classification_id,
            )
        for em in await self._kg.find_escalation_method_to_data():
            g("escalation_method_to_data", (em.principal_id, em.target_id, em.resource_id)).add(
                (
                    em.principal_id,
                    em.target_id,
                    em.resource_id,
                    em.data_classification_id,
                ),
                em.data_type,
                method=em.method,
                data_type=em.data_type,
                sink=em.data_classification_id,
            )

        paths = [
            AttackPath(
                path_type=path_type,
                severity=_SEVERITY[path_type],
                title=_title(path_type, grp),
                entities=tuple(sorted(grp.entities)),
                evidence=tuple(grp.evidence),
                count=len(grp.evidence),
                sink_id=grp.sink,
                kev=grp.kev,
                epss=grp.max_epss,
            )
            for (path_type, _subject), grp in groups.items()
        ]
        paths.sort(key=lambda p: (-p.severity, -p.count, p.title))
        return paths


__all__ = ["AttackPath", "AttackPathRanker"]
