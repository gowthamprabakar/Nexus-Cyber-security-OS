"""Shared moto-IAM listing helper — drives identity's REAL readers against a moto IAM client.

Builds an ``IdentityListing`` from moto via identity's own ``_list_*`` readers, ready to feed to the
real grant extractors (``_synthesize_admin_grants`` / ``_fine_grained_grants`` /
``_externally_trusted_arns``). No fake IAM — moto is the substrate. The canonical glue for the
whole-environment scene; the older path-1/4/8 e2es predate it and keep their own local copies.
"""

from __future__ import annotations

from identity.tools.aws_iam import (
    IdentityListing,
    _list_groups,
    _list_policies,
    _list_roles,
    _list_users,
)


def list_moto_identities(iam: object) -> IdentityListing:
    """Build an :class:`IdentityListing` from a moto IAM client via identity's REAL readers."""
    degraded: list[dict[str, str]] = []
    return IdentityListing(
        users=tuple(_list_users(iam, degraded)),
        roles=tuple(_list_roles(iam, degraded)),
        groups=tuple(_list_groups(iam, degraded)),
        policies=tuple(_list_policies(iam, degraded)),
        degraded=tuple(degraded),
    )


__all__ = ["list_moto_identities"]
