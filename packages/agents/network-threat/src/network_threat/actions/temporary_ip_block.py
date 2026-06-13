"""Temporary IP block action (D.4 v0.2 Task 14).

The **only** action D.4 emits at v0.2 is a **TTL-bounded, auto-expiring** IP block (a
proposal in v0.2; the cloud security-group/firewall apply happens via the gated lane).
Per **Q4 / WI-N8 / WI-N10** there are NO permanent blocks, NO IP-range blocks, NO
BGP/routing changes, and NO private-range blocks — those are deferred to the A.1
Remediation cycle (WI-N9). `assert_block_authorized` is the **hard code-level guard**
(mirrors D.3's `assert_authorized`); it backstops pause-triggers #11 + #12.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from network_threat.schemas import NetworkFinding, Severity

#: The only action type authorized at v0.2.
AUTHORIZED_ACTION_TYPE = "temporary_ip_block"

#: IP block TTL hard cap (seconds) — per benchmark safety H5: blocks are never permanent.
MAX_TTL_SECONDS = 3600

#: Findings at these severities warrant a TTL-bounded block of their public source IP(s).
_BLOCK_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})


class UnauthorizedNetworkActionError(RuntimeError):
    """A forbidden network action (permanent / untimed / private-range / non-block)."""


def _is_private_ip_range(target_ip: str) -> bool:
    """True for RFC1918 private, loopback, link-local, reserved, or multicast addresses."""
    addr = ipaddress.ip_address(target_ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def assert_block_authorized(action_type: str, target_ip: str, ttl_seconds: int | None) -> None:
    """Hard guard for network block actions (Q4 / WI-N8 / WI-N10). Raises unless:

    - ``action_type`` is ``"temporary_ip_block"`` (permanent / BGP → A.1 cycle),
    - ``ttl_seconds`` is set + within 1..3600 (never permanent),
    - ``target_ip`` is a valid, **public** address (never a private range).
    """
    if action_type != AUTHORIZED_ACTION_TYPE:
        raise UnauthorizedNetworkActionError(
            f"action {action_type!r} is not authorized at D.4 v0.2 — only "
            f"'temporary_ip_block' (TTL-bounded); permanent blocks + BGP/routing changes "
            f"→ A.1 Remediation cycle"
        )
    if ttl_seconds is None or ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        raise UnauthorizedNetworkActionError(
            f"TTL required (1-{MAX_TTL_SECONDS} seconds); never permanent — per WI-N8 + "
            f"benchmark safety H5 (got {ttl_seconds!r})"
        )
    try:
        is_private = _is_private_ip_range(target_ip)
    except ValueError as exc:
        raise UnauthorizedNetworkActionError(
            f"invalid target IP {target_ip!r} — cannot authorize a block"
        ) from exc
    if is_private:
        raise UnauthorizedNetworkActionError(
            f"private-range blocking forbidden at v0.2 ({target_ip}) — per WI-N10 + "
            f"benchmark safety H5"
        )


@dataclass(frozen=True, slots=True)
class TemporaryIpBlock:
    target_ip: str
    ttl_seconds: int
    reason: str
    requested_at: str  # ISO 8601
    expires_at: str  # ISO 8601 — requested_at + ttl
    action_type: str = AUTHORIZED_ACTION_TYPE

    @property
    def is_temporary(self) -> bool:
        """Always True — the block carries a finite TTL and auto-expires."""
        return True


def request_temporary_ip_block(
    target_ip: str, *, ttl_seconds: int, reason: str, requested_at: datetime
) -> TemporaryIpBlock:
    """Emit a TTL-bounded IP block request. Guarded by `assert_block_authorized` — a
    permanent / untimed / private-range / non-block attempt raises."""
    assert_block_authorized(AUTHORIZED_ACTION_TYPE, target_ip, ttl_seconds)
    expires = requested_at + timedelta(seconds=ttl_seconds)
    return TemporaryIpBlock(
        target_ip=target_ip,
        ttl_seconds=ttl_seconds,
        reason=reason,
        requested_at=requested_at.isoformat(),
        expires_at=expires.isoformat(),
    )


def build_temporary_ip_blocks(
    findings: Sequence[NetworkFinding],
    *,
    requested_at: datetime,
    ttl_seconds: int = MAX_TTL_SECONDS,
) -> list[TemporaryIpBlock]:
    """Emit a TTL-bounded block per public source IP of each HIGH/CRITICAL finding (Phase C SS2).

    The run-flow integration point that makes ``assert_block_authorized`` load-bearing: every block
    routes through ``request_temporary_ip_block`` -> ``assert_block_authorized``. A private/invalid
    source IP is correctly NOT blockable at v0.2 (WI-N10) — the guard rejects it and we skip it, so
    the guard stays authoritative rather than being pre-empted by a looser filter. Each public IP is
    blocked at most once per run.
    """
    blocks: list[TemporaryIpBlock] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.severity not in _BLOCK_SEVERITIES:
            continue
        for src_ip in finding.src_ips:
            if not src_ip or src_ip in seen:
                continue
            try:
                block = request_temporary_ip_block(
                    src_ip,
                    ttl_seconds=ttl_seconds,
                    reason=f"{finding.title} ({finding.finding_id})",
                    requested_at=requested_at,
                )
            except UnauthorizedNetworkActionError:
                continue  # private / invalid IP — not blockable at v0.2 (guard authoritative)
            seen.add(src_ip)
            blocks.append(block)
    return blocks


def temporary_ip_blocks_to_json(blocks: Sequence[TemporaryIpBlock]) -> str:
    """Render TTL-bounded blocks as the additive ``ip_block_actions.json`` workspace artifact."""
    return json.dumps([asdict(b) for b in blocks], indent=2)
