"""Azure RBAC role-assignment reader — the cross-cloud access leg (gap #13).

Resolves which Azure AD principal can read which Blob container, so identity can write the
SAME ``IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE`` spine edge it writes for AWS IAM — keyed by
the container's canonical ``azure_blob_uri`` (the key data-security's storage writer uses), so the
cloud-agnostic ``kg_query`` detectors (path 4 fine-grained data exposure) fire on Azure with no
detector change.

The client is an injectable ``AzureRbacReader`` Protocol, so this is unit-testable without the
azure-mgmt SDK. ``blob_read_grants`` is the part with teeth: it keeps only assignments whose role
grants blob *data* read and whose scope resolves to a concrete (account, container).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from charter.canonical import azure_blob_uri

#: Built-in Azure roles that grant blob *data* read. Control-plane roles (Owner/Contributor) are
#: deliberately excluded — they manage the account but don't grant data-plane read without keys.
BLOB_READ_ROLES = frozenset(
    {
        "Storage Blob Data Reader",
        "Storage Blob Data Contributor",
        "Storage Blob Data Owner",
    }
)

#: Pull (account, container) out of a container-scoped role-assignment scope, case-insensitively.
_CONTAINER_SCOPE_RE = re.compile(
    r"/storageAccounts/(?P<account>[^/]+)"
    r"/blobServices/default/containers/(?P<container>[^/]+)/?$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class AzureRoleAssignment:
    """One RBAC role assignment: a principal granted a role at a scope."""

    principal_id: str
    role_name: str
    scope: str


class AzureRbacReader(Protocol):
    def list_role_assignments(self) -> list[dict[str, Any]]: ...


class AzureRbacLiveReader:
    """Reads live Azure RBAC role assignments via an injectable client."""

    __slots__ = ("_client",)

    def __init__(self, client: AzureRbacReader) -> None:
        self._client = client

    def read(self) -> tuple[AzureRoleAssignment, ...]:
        out: list[AzureRoleAssignment] = []
        for raw in self._client.list_role_assignments():
            if not isinstance(raw, dict):
                continue
            principal = str(raw.get("principal_id", ""))
            role = str(raw.get("role_name", ""))
            scope = str(raw.get("scope", ""))
            if principal and role and scope:
                out.append(AzureRoleAssignment(principal, role, scope))
        return tuple(out)


def blob_read_grants(assignments: tuple[AzureRoleAssignment, ...]) -> list[tuple[str, str]]:
    """``(principal_id, azure_blob_uri)`` for each container-scoped blob-read assignment.

    Fine-grained by design (path 4 = least-privilege violation): only **container-scoped**
    assignments resolve to a concrete container key; broader account/subscription scopes are not
    fine-grained and are skipped. Deduped, order-preserving.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for a in assignments:
        if a.role_name not in BLOB_READ_ROLES:
            continue
        m = _CONTAINER_SCOPE_RE.search(a.scope)
        if m is None:
            continue
        grant = (a.principal_id, azure_blob_uri(m["account"], m["container"]))
        if grant not in seen:
            seen.add(grant)
            out.append(grant)
    return out


def external_trust_grants(
    assignments: tuple[AzureRoleAssignment, ...], guest_principal_ids: frozenset[str]
) -> list[tuple[str, str]]:
    """``(principal_id, azure_blob_uri)`` for blob-read grants held by a **guest** principal (path 8).

    A subset of :func:`blob_read_grants` filtered to principals in ``guest_principal_ids`` — the
    B2B guests identity's AD listing flags via ``AzureAdUser.is_guest`` (``userType == 'Guest'``).
    These are the externally-trusted principals path 8 marks.
    """
    return [g for g in blob_read_grants(assignments) if g[0] in guest_principal_ids]


__all__ = [
    "BLOB_READ_ROLES",
    "AzureRbacLiveReader",
    "AzureRbacReader",
    "AzureRoleAssignment",
    "blob_read_grants",
    "external_trust_grants",
]
