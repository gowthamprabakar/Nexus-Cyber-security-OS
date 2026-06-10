"""DNS query pattern detection (D.4 v0.2 Task 12).

Adds three **additive** DNS-pattern signals over `DnsEvent` input: **tunneling**
indicators (long encoded subdomains), **suspicious-TLD** detection, and a repeated-query
(**DNS beaconing**) proxy. New helpers — the v0.1 DGA detector + eval cases are untouched
(WI-N5 byte-identical); callers opt in.
"""

from __future__ import annotations

from collections.abc import Sequence

from network_threat.schemas import DnsEvent

#: TLDs over-represented in abuse / cheap-registration campaigns.
SUSPICIOUS_TLDS = frozenset(
    {"tk", "top", "xyz", "gq", "ml", "ga", "cf", "work", "click", "country", "kim"}
)


def has_suspicious_tld(domain: str) -> bool:
    """True if the domain's effective TLD is in `SUSPICIOUS_TLDS`."""
    parts = domain.lower().strip().rstrip(".").rsplit(".", 1)
    tld = parts[-1] if parts else ""
    return tld in SUSPICIOUS_TLDS


def is_dns_tunneling(
    query_name: str, *, subdomain_min_length: int = 50, min_labels: int = 4
) -> bool:
    """Flag DNS tunneling: a very long label (data encoded in a subdomain) OR many labels
    whose combined length is large."""
    d = query_name.lower().strip().rstrip(".")
    if not d:
        return False
    labels = d.split(".")
    longest = max((len(label) for label in labels), default=0)
    return longest >= subdomain_min_length or (
        len(labels) >= min_labels and len(d) >= subdomain_min_length
    )


def repeated_query_domains(
    events: Sequence[DnsEvent], *, min_count: int = 10
) -> list[tuple[str, int]]:
    """Domains queried at least ``min_count`` times — a DNS-beaconing proxy (true
    periodicity is the flow beacon detector's job). Sorted by count then name."""
    counts: dict[str, int] = {}
    for e in events:
        counts[e.query_name] = counts.get(e.query_name, 0) + 1
    out = [(d, c) for d, c in counts.items() if c >= min_count]
    out.sort(key=lambda x: (-x[1], x[0]))
    return out
