"""Kubeconfig credential safety (D.6 v0.2 Task 15, WI-K9).

Kubeconfig carries bearer tokens, client certs, and client keys. Per **WI-K9** (mirroring
D.8's WI-T8) those secrets must **never** land on a repr-able field or in a log line:
`SafeKubeconfig` holds only a path reference (its repr shows the path, never content), and
`redact_kubeconfig` / `redact_secret_value` scrub secret values before anything is logged.
"""

from __future__ import annotations

import re

#: Kubeconfig keys whose values are secret and must be redacted before logging.
SECRET_KEYS = (
    "token",
    "client-certificate-data",
    "client-key-data",
    "password",
    "client-secret",
    "id-token",
    "refresh-token",
)

_REDACTED = "***REDACTED***"
_SECRET_LINE_RE = re.compile(
    r"^(\s*(?:" + "|".join(re.escape(k) for k in SECRET_KEYS) + r")\s*:\s*).+$",
    re.IGNORECASE,
)


class SafeKubeconfig:
    """A kubeconfig reference that never exposes secret content via repr/str/logs.

    Holds only the path; the file (with its tokens/certs) is read per-call by the client,
    never cached on a repr-able field (WI-K9)."""

    __slots__ = ("_path",)

    def __init__(self, path: str) -> None:
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    def __repr__(self) -> str:
        return f"SafeKubeconfig(path={self._path!r})"

    __str__ = __repr__


def redact_secret_value(key: str, value: str) -> str:
    """Redact ``value`` if ``key`` names a kubeconfig secret; else return it unchanged."""
    return _REDACTED if key.lower() in SECRET_KEYS else value


def redact_kubeconfig(text: str) -> str:
    """Return kubeconfig text with every secret value replaced by a redaction marker —
    safe to log. Non-secret lines are preserved verbatim."""
    return "\n".join(_SECRET_LINE_RE.sub(rf"\1{_REDACTED}", line) for line in text.splitlines())
