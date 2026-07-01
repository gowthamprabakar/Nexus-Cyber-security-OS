"""Leaked Azure service-principal secret detector (slice #3 on Azure).

An Azure SP credential in code is not a single token or a standard JSON file (unlike an AWS key id or
a GCP SA-key JSON) — it is a *set* of env/config values: a client-secret (opaque) beside a client-id
(``appId``, a GUID) and a tenant-id. So detection is structural over the value SET: when a client
*secret* is present alongside a GUID client-id, the SP is leaked, and the non-secret **client-id**
(the appId — Azure AD's public identifier) is the convergence key. Only its
``secret_fingerprint`` is returned; the secret value is never retained (operator-chosen hashed
convergence, so the approved-plaintext allowlist stays AWS-only).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from charter.canonical import secret_fingerprint

if TYPE_CHECKING:
    from collections.abc import Sequence

#: Env/config key names (case-insensitive) that carry an Azure SP client-id / client-secret.
_CLIENT_ID_KEYS = ("azure_client_id", "client_id", "appid", "arm_client_id")
_CLIENT_SECRET_KEYS = ("azure_client_secret", "client_secret", "arm_client_secret")
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def leaked_azure_sp_secrets(env: Sequence[tuple[str, str]]) -> list[str]:
    """``secret_fingerprint(client_id)`` when a leaked Azure SP credential set is present.

    A leak requires BOTH a client *secret* (a value under a secret key) AND a GUID client-id — a lone
    appId GUID is a public identifier, not a leaked credential (the precision crux). Returns the
    fingerprint of the client-id only. At most one per env context; empty if not a full SP cred set.
    """
    lookup = {k.lower(): v for k, v in env}
    if not any(lookup.get(k) for k in _CLIENT_SECRET_KEYS):
        return []
    for key in _CLIENT_ID_KEYS:
        value = lookup.get(key, "")
        if _GUID_RE.match(value):
            return [secret_fingerprint(value)]
    return []


__all__ = ["leaked_azure_sp_secrets"]
