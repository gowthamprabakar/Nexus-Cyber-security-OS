"""Tests for `investigation.tools.ioc_extractor` (D.7 Task 6).

Regex + heuristic IOC extraction. Takes a string or a nested dict
(e.g. a sibling finding's payload) and pulls out indicators of
compromise typed as `IocItem` from `investigation.schemas`.

Production contract:

- `extract_iocs(content)` accepts `str | dict | list | tuple`. Walks
  nested structures; flattens leaf strings into the matcher.
- Returns `tuple[IocItem, ...]` — deduplicated, ordered by first
  appearance.
- Detected types: ipv4, ipv6, domain, url, sha256, sha1, md5, email,
  cve.
- Aggressively ignores false positives (e.g. version strings like
  "1.2.3.4" → matches the ipv4 regex but is filtered by a context heuristic;
  see test cases).
"""

from __future__ import annotations

from investigation.schemas import IocType
from investigation.tools.ioc_extractor import extract_iocs

# ---------------------------- IPv4 ------------------------------------


def test_extracts_ipv4_from_plain_text() -> None:
    iocs = extract_iocs("The attacker connected from 192.0.2.1 and 198.51.100.42")
    assert {(i.type, i.value) for i in iocs} == {
        (IocType.IPV4, "192.0.2.1"),
        (IocType.IPV4, "198.51.100.42"),
    }


def test_filters_loopback_and_zero_ipv4() -> None:
    """127.0.0.1 and 0.0.0.0 are RFC-valid but never useful as IOCs."""
    iocs = extract_iocs("Connected to 127.0.0.1 and 0.0.0.0; also 198.51.100.7")
    values = {i.value for i in iocs if i.type is IocType.IPV4}
    assert values == {"198.51.100.7"}


# ---------------------------- Domain ----------------------------------


def test_extracts_domains() -> None:
    iocs = extract_iocs("Beacon to evil.example.com and c2.attacker.org")
    values = {i.value for i in iocs if i.type is IocType.DOMAIN}
    assert values == {"evil.example.com", "c2.attacker.org"}


# ---------------------------- URL ------------------------------------


def test_extracts_url_and_does_not_double_emit_domain_inside_it() -> None:
    """If a URL contains a domain, emit the URL only — operator wants
    the more-specific IOC.
    """
    iocs = extract_iocs("Stage 2 fetched https://evil.example.com/payload.exe")
    types = {i.type for i in iocs}
    assert IocType.URL in types
    # The domain inside the URL is not separately emitted.
    domains = [i.value for i in iocs if i.type is IocType.DOMAIN]
    assert "evil.example.com" not in domains


# ---------------------------- Hashes ---------------------------------


def test_extracts_sha256_sha1_md5() -> None:
    sha256 = "a" * 64
    sha1 = "b" * 40
    md5 = "c" * 32
    iocs = extract_iocs(f"hashes: {sha256}  {sha1}  {md5}")
    types = {(i.type, i.value) for i in iocs}
    assert (IocType.SHA256, sha256) in types
    assert (IocType.SHA1, sha1) in types
    assert (IocType.MD5, md5) in types


def test_does_not_misclassify_hex_strings_that_are_not_hashes() -> None:
    """A 33-char hex string is neither MD5 (32) nor SHA-1 (40) — drop it."""
    iocs = extract_iocs(f"random hex {'a' * 33}")
    assert all(i.type not in {IocType.MD5, IocType.SHA1} for i in iocs)


# ---------------------------- Email ---------------------------------


def test_extracts_email() -> None:
    iocs = extract_iocs("Phishing came from attacker@evil.example.com")
    assert any(i.type is IocType.EMAIL and i.value == "attacker@evil.example.com" for i in iocs)


# ---------------------------- CVE ----------------------------------


def test_extracts_cve_uppercase() -> None:
    iocs = extract_iocs("Exploited CVE-2024-12345 on the vulnerable host")
    assert any(i.type is IocType.CVE and i.value == "CVE-2024-12345" for i in iocs)


def test_rejects_cve_lowercase() -> None:
    """CVE IDs are canonically uppercase. Lowercase cve-... is not extracted."""
    iocs = extract_iocs("cve-2024-99999 was mentioned but malformed")
    assert all(i.type is not IocType.CVE for i in iocs)


# ---------------------------- Nested input ----------------------------


def test_walks_nested_dict() -> None:
    payload = {
        "finding": {
            "evidence": [
                {"network": {"remote_ip": "192.0.2.7"}},
                {"hashes": ["a" * 64]},
            ],
            "details": "Talked to evil.example.com",
        }
    }
    iocs = extract_iocs(payload)
    values = {i.value for i in iocs}
    assert "192.0.2.7" in values
    assert "a" * 64 in values
    assert "evil.example.com" in values


def test_walks_list_input() -> None:
    iocs = extract_iocs(["198.51.100.5", "evil.example.com", "ignored"])
    assert {i.value for i in iocs} >= {"198.51.100.5", "evil.example.com"}


# ---------------------------- Dedup + ordering -----------------------


def test_dedups_repeated_iocs_preserving_first_appearance() -> None:
    iocs = extract_iocs("Hit 192.0.2.1, then again 192.0.2.1, then 198.51.100.42")
    ipv4s = [i.value for i in iocs if i.type is IocType.IPV4]
    assert ipv4s == ["192.0.2.1", "198.51.100.42"]


def test_returns_tuple_not_list() -> None:
    """API stability — `tuple` for hashability + frozen-friendly use in
    `IncidentReport.iocs`.
    """
    iocs = extract_iocs("none here")
    assert isinstance(iocs, tuple)


# ---------------------------- Empty input ----------------------------


def test_empty_string_returns_empty_tuple() -> None:
    assert extract_iocs("") == ()


def test_empty_dict_returns_empty_tuple() -> None:
    assert extract_iocs({}) == ()
