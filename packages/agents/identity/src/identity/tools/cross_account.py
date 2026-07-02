"""Cross-account trust detector (W3) — the cross-account attack path.

A role whose trust policy lets a **foreign account** assume it is a cross-account foothold: that
external principal can assume the role and reach whatever the role can. This parses each role's
``assume_role_policy_document`` and emits ``(external_principal, role_arn)`` for every trusted
principal from a different account (or the anonymous ``*``). The driver marks the external principal
(``record_external_trust``) and writes the ``ASSUMES`` edge (``record_assume_grants``) — both existing
writers — so the walk ``external principal --ASSUMES--> role --HAS_ACCESS_TO--> data`` emerges. A
same-account or service principal is NOT cross-account (the precision crux).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

    from identity.tools.aws_iam import IamRole


def _account_of(arn: str) -> str:
    """The 12-digit account id from an ARN (field 4), or "" if not an account ARN."""
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else ""


def _is_externalid_guarded(statement: dict[str, Any]) -> bool:
    """True if the trust statement requires an ``sts:ExternalId`` — the confused-deputy mitigation.

    A cross-account role gated by ExternalId is NOT freely assumable: the external party must know a
    shared secret. Flagging it as escalation is a false positive (NEX-408 precision fix), so such
    statements are skipped. Checks every operator's condition keys for ``sts:externalid`` (case-insens).
    """
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False
    return any(
        isinstance(operands, dict) and any(str(k).lower() == "sts:externalid" for k in operands)
        for operands in condition.values()
    )


def cross_account_trust_grants(roles: Sequence[IamRole]) -> list[tuple[str, str]]:
    """``(external_principal, role_arn)`` for each role trusting a foreign account / ``*``.

    Parses ``Allow`` statements' ``Principal.AWS`` (str or list). A principal whose account differs
    from the role's own account, or the anonymous ``*``, is cross-account. Same-account and non-AWS
    (service/federated) principals are skipped. **A statement gated by ``sts:ExternalId`` is skipped**
    (NEX-408: not freely assumable — the confused-deputy mitigation). Deduped, order-stable.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for role in roles:
        home = _account_of(role.arn)
        statements = role.assume_role_policy_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            if _is_externalid_guarded(stmt):
                continue
            principal = stmt.get("Principal", {})
            aws = principal.get("AWS") if isinstance(principal, dict) else None
            principals = [aws] if isinstance(aws, str) else (aws if isinstance(aws, list) else [])
            for p in principals:
                p = str(p)
                if p == "*" or (_account_of(p) and _account_of(p) != home):
                    grant = (p, role.arn)
                    if grant not in seen:
                        seen.add(grant)
                        out.append(grant)
    return out


__all__ = ["cross_account_trust_grants"]
