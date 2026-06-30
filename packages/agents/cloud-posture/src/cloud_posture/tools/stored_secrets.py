"""Stored-secret detector (W6) — a workload that embeds a long-lived credential.

A public workload carrying a long-lived AWS access key in its environment is a credential-access
foothold: compromise the box, read the key, become whoever owns it. This extracts the **access key
ID** (the approved-plaintext identifier — never the secret access key) from a workload's env values
and emits ``(resource_arn, access_key_id)``. The SECRET node converges with identity's
``OWNS``/``OWNED_BY`` (same key id), so the walk
``workload --STORES_SECRET--> secret --OWNED_BY--> identity --HAS_ACCESS_TO--> data`` emerges.

Injectable input (the env values), so it is unit-tested without reading live ECS/Lambda task
definitions; the live env reader is the operator-gated follow-on.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

#: AWS access key ID — the NON-secret identifier (CloudTrail logs it). The matching secret access
#: key is never extracted or stored.
_AKIA_RE = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}")


def stored_secret_grants(
    workloads: Sequence[tuple[str, Sequence[str]]],
) -> list[tuple[str, str]]:
    """``(resource_arn, access_key_id)`` for each workload env value that holds an AWS key id.

    ``workloads`` is ``(resource_arn, env_values)``. Only the access key ID is extracted (the secret
    value is irrelevant — the id is the convergence key). Deduped, order-stable.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for resource_arn, env_values in workloads:
        for value in env_values:
            m = _AKIA_RE.search(str(value))
            if m is None:
                continue
            grant = (resource_arn, m.group(0))
            if grant not in seen:
                seen.add(grant)
                out.append(grant)
    return out


__all__ = ["stored_secret_grants"]
