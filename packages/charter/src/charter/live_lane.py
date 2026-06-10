"""Live-eval lane gating contract — Pattern D (hoisted, D.2 v0.2 Task 3).

Hoisted from F.3 cloud-posture (`NEXUS_LIVE_AWS`), D.5 multi-cloud-posture
(`NEXUS_LIVE_AZURE` / `NEXUS_LIVE_GCP`), and D.1 vulnerability
(`NEXUS_LIVE_REGISTRY_*`) into the charter for cross-agent reuse — D.2 Identity is
the 4th consumer (its `NEXUS_LIVE_IDENTITY_*` lanes, Tasks 16-17). Per ADR-007 the
canonical gating shape lives in one place; agents adopt it instead of re-deriving it.

The contract: a live-eval lane is OFF unless its ``NEXUS_LIVE_*=1`` env var is set;
when set, an optional per-cloud **reachability probe** gates the actual run, else a
skip message with copy-paste setup instructions is surfaced. The per-cloud probes,
the setup-instruction text, and the env-var names stay in each agent — this module
is cloud-agnostic mechanism only.
"""

from __future__ import annotations

import os
from collections.abc import Callable


def nexus_live_enabled(env_var: str) -> bool:
    """True iff the live lane named by ``env_var`` is enabled (``<env_var>=1``)."""
    return os.environ.get(env_var) == "1"


def live_skip_reason(
    env_var: str,
    label: str,
    setup: str,
    probe: Callable[[], tuple[bool, str]] | None = None,
) -> str | None:
    """`None` when the lane is enabled AND (if a probe is given) reachable;
    otherwise the ``pytest.skip`` message with copy-paste setup instructions.

    - lane disabled → returns ``setup``.
    - lane enabled and ``probe()`` returns ``(False, reason)`` →
      ``"<env_var>=1 set but <label> is unreachable (<reason>). <setup>"``.
    - lane enabled and reachable (or no probe given) → ``None``.

    ``label`` is the human cloud/service name ("AWS", "Azure", "ECR", …); ``reason``
    is the secret-free, traceback-free type name the probe returns.
    """
    if not nexus_live_enabled(env_var):
        return setup
    if probe is not None:
        ok, reason = probe()
        if not ok:
            return f"{env_var}=1 set but {label} is unreachable ({reason}). {setup}"
    return None
