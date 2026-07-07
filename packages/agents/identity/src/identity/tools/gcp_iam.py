"""GCP IAM bucket-binding reader — the cross-cloud access leg (gap #13).

Resolves which GCP IAM member can read which GCS bucket, so identity can write the SAME
``IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE`` spine edge it writes for AWS IAM — keyed by the
bucket's canonical ``gcs_uri`` (the key data-security's storage writer uses), so the cloud-agnostic
``kg_query`` detectors (path 4 fine-grained data exposure) fire on GCP with no detector change.

The client is an injectable ``GcpIamReader`` Protocol, so this is unit-testable without the
google-cloud-storage SDK. ``storage_read_grants`` keeps only bindings whose role grants object read
and flattens each binding's members into per-member grants.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from charter.canonical import gcs_uri, secret_fingerprint

#: GCP roles that grant object *read* on a bucket (data-plane), excluding public members which the
#: storage writer already handles as ``is_public``.
STORAGE_READ_ROLES = frozenset(
    {
        "roles/storage.objectViewer",
        "roles/storage.objectAdmin",
        "roles/storage.admin",
        "roles/storage.legacyObjectReader",
    }
)
#: Members that mean "the whole internet" — public exposure, owned by the storage writer, not a grant.
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


@dataclass(frozen=True, slots=True)
class GcpIamBinding:
    """One bucket-level IAM binding: a role granted to members on a bucket."""

    bucket: str
    role: str
    members: tuple[str, ...]


class GcpIamReader(Protocol):
    def list_bucket_bindings(self) -> list[dict[str, Any]]: ...


class GcpIamLiveReader:
    """Reads live GCS bucket IAM bindings via an injectable client."""

    __slots__ = ("_client",)

    def __init__(self, client: GcpIamReader) -> None:
        self._client = client

    def read(self) -> tuple[GcpIamBinding, ...]:
        out: list[GcpIamBinding] = []
        for raw in self._client.list_bucket_bindings():
            if not isinstance(raw, dict):
                continue
            bucket = str(raw.get("bucket", ""))
            role = str(raw.get("role", ""))
            members = raw.get("members", [])
            if bucket and role and isinstance(members, list):
                out.append(GcpIamBinding(bucket, role, tuple(str(m) for m in members)))
        return tuple(out)


def storage_read_grants(bindings: tuple[GcpIamBinding, ...]) -> list[tuple[str, str]]:
    """``(member, gcs_uri)`` for each object-read binding's non-public members.

    Deduped, order-preserving. Public members (``allUsers``) are dropped — bucket-level public
    exposure is the storage writer's ``is_public`` leg, not a per-principal grant.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for b in bindings:
        if b.role not in STORAGE_READ_ROLES:
            continue
        for member in b.members:
            if member in _PUBLIC_MEMBERS:
                continue
            grant = (member, gcs_uri(b.bucket))
            if grant not in seen:
                seen.add(grant)
                out.append(grant)
    return out


_OWNER_ROLE = "roles/owner"
#: NEX-402 GCP privesc-method depth: each role-set → the (method, via_action) escalation it enables.
#: A member holding any role in a set can reach Owner by that technique. ``roles/owner`` is the target,
#: never a source. Three distinct methods (was one), mirroring AWS's method breadth.
_ESCALATION_METHODS: tuple[tuple[frozenset[str], str, str], ...] = (
    (
        frozenset({"roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"}),
        "self_grant_admin",
        "resourcemanager.projects.setIamPolicy",
    ),
    (  # can rewrite a custom role's permissions to include admin
        frozenset({"roles/iam.roleAdmin", "roles/iam.organizationRoleAdmin"}),
        "role_rewrite",
        "iam.roles.update",
    ),
    (  # can mint a key for a privileged service account and assume it
        frozenset({"roles/iam.serviceAccountKeyAdmin"}),
        "credential_mint",
        "iam.serviceAccountKeys.create",
    ),
    (  # can mint an OAuth/OIDC token for a target SA and act as it
        frozenset({"roles/iam.serviceAccountTokenCreator"}),
        "sa_impersonation",
        "iam.serviceAccounts.getOpenIdToken",
    ),
)


def escalation_grants(bindings: tuple[GcpIamBinding, ...]) -> list[tuple[str, str, str, str]]:
    """``(member, owner_member, method, via_action)`` GCP privilege escalation → CAN_ESCALATE_TO.

    Detects the members who can reach ``roles/owner`` by any of the modelled techniques (NEX-402:
    self-grant via setIamPolicy, custom-role rewrite, or SA-key mint). Same 4-tuple edge contract
    AWS/Azure use; an edge is emitted ONLY when an Owner target is resolved (the precision crux).
    Expects **project-level** bindings. Deduped per (member, owner, method), order-stable.
    """
    owners = {m for b in bindings if b.role == _OWNER_ROLE for m in b.members}
    if not owners:
        return []
    out: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for roles, method, action in _ESCALATION_METHODS:
        sources = {m for b in bindings if b.role in roles for m in b.members} - owners
        for src in sorted(sources):
            for owner in sorted(owners):
                if (src, owner, method) not in seen:
                    seen.add((src, owner, method))
                    out.append((src, owner, method, action))
    return out


@dataclass(frozen=True, slots=True)
class GcpServiceAccountKey:
    """A GCP service-account key: the owning SA (the IDENTITY node key) + the key's non-secret id."""

    service_account: str
    private_key_id: str


def sa_key_ownership(keys: tuple[GcpServiceAccountKey, ...]) -> list[tuple[str, str]]:
    """``(service_account, secret_fingerprint(private_key_id))`` for each SA key (slice #3 GCP owner).

    The fingerprint is the SAME convergence key appsec computes from a leaked key's
    ``private_key_id`` (:func:`appsec.gcp_sa_key.leaked_sa_key_fingerprints`), so an SA key leaked in
    code and its owning service account collapse onto one SECRET node — hashed convergence, nothing
    readable stored. Deduped, order-stable.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for k in keys:
        grant = (k.service_account, secret_fingerprint(k.private_key_id))
        if grant not in seen:
            seen.add(grant)
            out.append(grant)
    return out


def _is_external(member: str, org_domain: str) -> bool:
    """True if a member is externally trusted: any-authenticated, or a user/group outside the org.

    ``allAuthenticatedUsers`` = any Google identity (outside the org). A ``user:``/``group:`` whose
    email domain != ``org_domain`` is a foreign collaborator. ``serviceAccount:`` (cross-project
    trust = deferred), ``allUsers`` (anonymous public, the storage is_public leg), and ``domain:``
    (explicit org config) are not flagged here.
    """
    if member == "allAuthenticatedUsers":
        return True
    prefix, _, principal = member.partition(":")
    if prefix in {"user", "group"} and "@" in principal:
        return principal.rsplit("@", 1)[-1].lower() != org_domain.lower()
    return False


def external_trust_grants(
    bindings: tuple[GcpIamBinding, ...], *, org_domain: str
) -> list[tuple[str, str]]:
    """``(member, gcs_uri)`` for object-read bindings held by an **externally-trusted** member (path 8).

    Identifies foreign collaborators (members outside ``org_domain``, plus ``allAuthenticatedUsers``)
    with object read — the externally-trusted principals path 8 marks. Deduped, order-preserving.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for b in bindings:
        if b.role not in STORAGE_READ_ROLES:
            continue
        for member in b.members:
            if not _is_external(member, org_domain):
                continue
            grant = (member, gcs_uri(b.bucket))
            if grant not in seen:
                seen.add(grant)
                out.append(grant)
    return out


__all__ = [
    "STORAGE_READ_ROLES",
    "GcpIamBinding",
    "GcpIamLiveReader",
    "GcpIamReader",
    "GcpServiceAccountKey",
    "escalation_grants",
    "external_trust_grants",
    "sa_key_ownership",
    "storage_read_grants",
]
