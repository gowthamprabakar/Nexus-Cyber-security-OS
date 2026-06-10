"""DGA detection refinement (D.4 v0.2 Task 11).

Refines the v0.1 entropy/bigram DGA detector with a **suffix allowlist** + a
**TLD-adjusted threshold** to cut false positives on legitimately randomized subdomains
(cloud / CDN hostnames). **Additive** — the v0.1 `detect_dga` + its eval cases are
untouched (WI-N5 byte-identical); callers opt into this refinement.
"""

from __future__ import annotations

#: Cloud / CDN suffixes whose subdomains are routinely random-looking but benign.
ALLOWLIST_SUFFIXES = frozenset(
    {
        "amazonaws.com",
        "cloudfront.net",
        "akamai.net",
        "akamaiedge.net",
        "azureedge.net",
        "windows.net",
        "googleusercontent.com",
        "googleapis.com",
        "fastly.net",
    }
)

#: The v0.1 detector's entropy threshold (bits/char) — kept aligned.
BASE_ENTROPY_THRESHOLD = 3.5


def is_allowlisted_suffix(domain: str) -> bool:
    """True if the domain is (or is a subdomain of) an allowlisted cloud/CDN suffix."""
    d = domain.lower().strip().rstrip(".")
    return any(d == suffix or d.endswith("." + suffix) for suffix in ALLOWLIST_SUFFIXES)


def dga_threshold(domain: str, *, base: float = BASE_ENTROPY_THRESHOLD) -> float:
    """The TLD-adjusted entropy threshold for a domain. Allowlisted cloud/CDN suffixes
    return ``inf`` (never flagged); everything else returns the base threshold."""
    if is_allowlisted_suffix(domain):
        return float("inf")
    return base


def is_dga_refined(domain: str, entropy: float, *, base: float = BASE_ENTROPY_THRESHOLD) -> bool:
    """Refined DGA decision: an allowlisted suffix is never DGA; otherwise the second-
    level entropy must meet the (TLD-adjusted) threshold."""
    return entropy >= dga_threshold(domain, base=base)
