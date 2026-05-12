"""`extract_iocs` — regex + heuristic IOC extraction (D.7 Task 6).

Pulls indicators of compromise out of a string, dict, list, or nested
combination. Returns typed `IocItem` tuples (matching the schema in
`investigation.schemas`).

D.7 uses this during Stage 2 sub-investigations (`ioc_pivot` sub-agent
walks the timeline + findings + audit payloads, extracts every IOC,
then queries threat intelligence and pivots). v0.1 ships pure regex
+ context filters; ML / NER-based extraction is deferred to Phase 1c.

**Heuristics that go beyond pure regex:**

- IPv4 filter — drops 127.0.0.x (loopback) and 0.0.0.0 (unspecified)
  even though they match the regex; they're never useful as IOCs.
- URL → suppress nested domain — when a URL is detected, the domain
  inside it is NOT separately emitted. Operators want the more-specific
  IOC.
- Hash length discrimination — a 33-char hex string is neither MD5 (32)
  nor SHA-1 (40); drop it rather than misclassify.

**Output discipline:**

- Returns `tuple` (not list) — hashable for use in `IncidentReport.iocs`
  + frozen-friendly across the agent driver.
- Deduplicates while preserving first-appearance order. The operator
  reads the report top-down, so the first hit is the one we keep.

Pure function — no async needed, no I/O. Wrapped through the agent
driver's tool registry (Task 12) so budget tracking still applies.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from investigation.schemas import IocItem, IocType

# Permissive patterns; the validators in `investigation.schemas.IocItem`
# enforce stricter canonical shapes at construction.
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
# Permissive URL pattern — captures everything from https:// to the
# next whitespace or end-of-string.
_URL_PATTERN = re.compile(r"https?://\S+")
# Strict CVE pattern — uppercase only, 4-digit year, ≥4-digit sequence.
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
# Email + domain: domain may follow a leading word boundary or `@`/`/`.
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_PATTERN = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_HEX64_PATTERN = re.compile(r"\b[0-9a-f]{64}\b")
_HEX40_PATTERN = re.compile(r"\b[0-9a-f]{40}\b")
_HEX32_PATTERN = re.compile(r"\b[0-9a-f]{32}\b")

# IPv4 octets that are RFC-valid but never useful as IOCs.
_IPV4_DROP_PREFIXES = ("127.", "0.0.0.0")  # noqa: S104 — string filter, not a bind address


def extract_iocs(content: Any) -> tuple[IocItem, ...]:
    """Walk `content` and return a deduplicated tuple of `IocItem`."""
    leaves = list(_collect_strings(content))
    if not leaves:
        return ()
    combined = "\n".join(leaves)
    if not combined.strip():
        return ()

    # Order matters: URL before domain, so a URL's nested domain is suppressed.
    seen: dict[tuple[IocType, str], None] = {}

    for ioc_type, value in _scan_ordered(combined):
        key = (ioc_type, value)
        if key in seen:
            continue
        # Attempt to construct the IocItem; if it fails the schema's
        # canonical validator, drop silently.
        try:
            IocItem(type=ioc_type, value=value)
        except (ValueError, TypeError):
            continue
        seen[key] = None

    return tuple(IocItem(type=t, value=v) for (t, v) in seen)


def _scan_ordered(text: str) -> Iterable[tuple[IocType, str]]:
    """Yield (type, value) pairs in a deliberate priority order.

    URL before DOMAIN — suppress nested domain emission.
    Higher-precision IOCs (CVE, email, hashes) before lower-precision (ipv4).
    """
    url_hits: list[str] = []

    for match in _URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(",.;:'\"")
        url_hits.append(url)
        yield IocType.URL, url

    # CVE
    for match in _CVE_PATTERN.finditer(text):
        yield IocType.CVE, match.group(0)

    # Email
    for match in _EMAIL_PATTERN.finditer(text):
        yield IocType.EMAIL, match.group(0)

    # Hashes — longest first so a SHA-256 isn't truncated as a SHA-1.
    for match in _HEX64_PATTERN.finditer(text):
        yield IocType.SHA256, match.group(0)
    for match in _HEX40_PATTERN.finditer(text):
        yield IocType.SHA1, match.group(0)
    for match in _HEX32_PATTERN.finditer(text):
        yield IocType.MD5, match.group(0)

    # IPv4 with drop filter for loopback / zero.
    for match in _IPV4_PATTERN.finditer(text):
        value = match.group(0)
        if any(value.startswith(pfx) for pfx in _IPV4_DROP_PREFIXES):
            continue
        yield IocType.IPV4, value

    # Domain — suppress any that appears inside an already-emitted URL.
    for match in _DOMAIN_PATTERN.finditer(text):
        domain = match.group(0)
        if any(domain in url for url in url_hits):
            continue
        # Skip email-local parts that happened to look domain-like; an
        # email's domain is already captured under IocType.EMAIL.
        if _appears_in_email_context(text, match.start(), domain):
            continue
        yield IocType.DOMAIN, domain


def _appears_in_email_context(text: str, start: int, domain: str) -> bool:
    """Is the matched domain the right-hand side of an email address?"""
    if start == 0:
        return False
    # Step back through allowed local-part chars and check for '@'.
    i = start - 1
    return text[i] == "@"


def _collect_strings(content: Any) -> Iterable[str]:
    """Flatten nested str/dict/list/tuple into a stream of leaf strings."""
    if content is None:
        return
    if isinstance(content, str):
        yield content
        return
    if isinstance(content, dict):
        for value in content.values():
            yield from _collect_strings(value)
        return
    if isinstance(content, (list, tuple)):
        for value in content:
            yield from _collect_strings(value)
        return
    # Numbers / bools / etc. — stringify for the regex pass.
    yield str(content)


__all__ = ["extract_iocs"]
