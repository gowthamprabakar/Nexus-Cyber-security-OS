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

from charter.canonical import gcs_uri

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


#: GCP roles whose permission set includes project-level ``setIamPolicy`` → self-grant any role
#: (privilege escalation). ``roles/owner`` can too, but it is already admin (the target, not a source).
_IAM_POLICY_WRITERS = frozenset(
    {"roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"}
)
_OWNER_ROLE = "roles/owner"
#: The GCP permission the escalation hinges on (for explainability / the edge's via).
_ESCALATION_ACTION = "resourcemanager.projects.setIamPolicy"


def escalation_grants(bindings: tuple[GcpIamBinding, ...]) -> list[tuple[str, str, str, str]]:
    """``(member, owner_member, method, via_action)`` GCP privilege escalation → CAN_ESCALATE_TO.

    A member granted ``roles/iam.securityAdmin`` or ``roles/resourcemanager.projectIamAdmin`` can
    set the project IAM policy and grant itself ``roles/owner``. The GCP implementation of the SAME
    edge contract AWS/Azure use (4-tuple, ``method=self_grant_admin``): an edge is emitted ONLY when
    an Owner target is resolved (the precision crux). Expects **project-level** bindings — escalation
    is a project-IAM concept, not bucket-scoped. Deduped, order-stable.
    """
    owners = {m for b in bindings if b.role == _OWNER_ROLE for m in b.members}
    if not owners:
        return []
    sources = {m for b in bindings if b.role in _IAM_POLICY_WRITERS for m in b.members} - owners
    out: list[tuple[str, str, str, str]] = []
    for src in sorted(sources):
        for owner in sorted(owners):
            out.append((src, owner, "self_grant_admin", _ESCALATION_ACTION))
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
    "escalation_grants",
    "external_trust_grants",
    "storage_read_grants",
]
