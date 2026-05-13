"""`enrich_with_intel` — bundled static threat-intel enrichment.

Per the D.4 plan, v0.1 ships **static bundled intel** sourced from
CISA KEV + abuse.ch + MITRE ATT&CK group references. Phase 1c replaces
this with the D.8 Threat Intel Agent (live VirusTotal + OTX feeds).

The enrichment runs as a pure function over a sequence of
`Detection` objects: for each, it consults the bundled tables and
annotates the detection's `evidence` dict with intel tags. **No
detection is dropped or added** — enrichment is additive only; the
detector outputs remain authoritative.

**Annotation surface** (added to `evidence['intel']` when matched):

- `intel.tags` — sorted tuple of applicable tags from `tag_legend`
  (e.g. `("dynamic_dns", "known_bad")`).
- `intel.matched_ip_cidr` — the CIDR an IP matched, when any.
- `intel.matched_domain_suffix` — the registered domain suffix matched.

**Match rules:**

- **DGA detections** — the `query_name` is checked against
  `known_bad_domains` (suffix match: a query for `foo.duckdns.org`
  matches the `duckdns.org` entry). DGA findings are usually
  random-looking labels; if they also match a dynamic-DNS suffix
  that's an extra-strong C2 signal.
- **Beacon detections** — `dst_ip` is checked against
  `known_bad_ip_cidrs` and `tor_exit_node_cidrs`.
- **Port-scan detections** — `src_ip` checked against
  `tor_exit_node_cidrs` and `known_bad_ip_cidrs`.
- **Suricata detections** — no enrichment (the Suricata signature
  itself is the intel; double-tagging would inflate severity).

**Severity uplift.** When at least one tag matches, the detection's
severity is bumped one level (MEDIUM → HIGH → CRITICAL). LOW/INFO are
not used by D.4 detectors; CRITICAL stays at CRITICAL. The uplift is
deterministic — same input → same output — and is the v0.1 substitute
for the Phase 1c reputation-score pipeline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Sequence
from functools import lru_cache
from importlib.resources import files
from typing import Any

from network_threat.schemas import Detection, FindingType, Severity

_LOG = logging.getLogger(__name__)


def enrich_with_intel(detections: Sequence[Detection]) -> tuple[Detection, ...]:
    """Return new Detection objects with `evidence.intel` annotations.

    Pure function over the input sequence — no I/O outside of loading
    the bundled JSON table (cached via `lru_cache` so repeated calls
    don't re-read the file).
    """
    intel = _load_intel()
    out: list[Detection] = []
    for det in detections:
        annotation = _annotate(det, intel=intel)
        if annotation is None:
            out.append(det)
            continue
        new_evidence = dict(det.evidence)
        new_evidence["intel"] = annotation
        new_severity = _maybe_uplift(det.severity, has_intel_hit=True)
        out.append(det.model_copy(update={"evidence": new_evidence, "severity": new_severity}))
    return tuple(out)


def _annotate(det: Detection, *, intel: dict[str, Any]) -> dict[str, Any] | None:
    """Return the `intel` sub-dict for one detection, or None if no match."""
    tags: set[str] = set()
    matched_cidr = ""
    matched_suffix = ""

    if det.finding_type == FindingType.DGA:
        qname = str(det.evidence.get("query_name") or "")
        suffix = _match_domain_suffix(qname, intel)
        if suffix:
            tags.add("known_bad")
            matched_suffix = suffix
            if suffix in _DYNAMIC_DNS_SUFFIXES:
                tags.add("dynamic_dns")
            if suffix in _URL_SHORTENERS:
                tags.add("url_shortener")
    elif det.finding_type == FindingType.BEACON:
        dst_ip = str(det.evidence.get("dst_ip") or det.dst_ip or "")
        cidr = _match_ip_cidr(dst_ip, intel["known_bad_ip_cidrs"])
        if cidr:
            tags.add("known_bad")
            matched_cidr = cidr
        tor_cidr = _match_ip_cidr(dst_ip, intel["tor_exit_node_cidrs"])
        if tor_cidr:
            tags.add("tor_exit")
            if not matched_cidr:
                matched_cidr = tor_cidr
    elif det.finding_type == FindingType.PORT_SCAN:
        src_ip = str(det.evidence.get("src_ip") or det.src_ip or "")
        cidr = _match_ip_cidr(src_ip, intel["known_bad_ip_cidrs"])
        if cidr:
            tags.add("known_bad")
            matched_cidr = cidr
        tor_cidr = _match_ip_cidr(src_ip, intel["tor_exit_node_cidrs"])
        if tor_cidr:
            tags.add("tor_exit")
            if not matched_cidr:
                matched_cidr = tor_cidr
    # SURICATA: no enrichment (signature carries the intel already).

    if not tags:
        return None
    annotation: dict[str, Any] = {"tags": tuple(sorted(tags))}
    if matched_cidr:
        annotation["matched_ip_cidr"] = matched_cidr
    if matched_suffix:
        annotation["matched_domain_suffix"] = matched_suffix
    return annotation


def _maybe_uplift(severity: Severity, *, has_intel_hit: bool) -> Severity:
    if not has_intel_hit:
        return severity
    if severity == Severity.MEDIUM:
        return Severity.HIGH
    if severity == Severity.HIGH:
        return Severity.CRITICAL
    return severity


def _match_domain_suffix(qname: str, intel: dict[str, Any]) -> str:
    """Return the matched `known_bad_domains` entry (longest-match) or ''."""
    if not qname:
        return ""
    lower = qname.lower().rstrip(".")
    best = ""
    for entry in intel["known_bad_domains"]:
        entry_l = entry.lower().rstrip(".")
        # Exact match OR proper-suffix match (must be preceded by '.').
        matches = lower == entry_l or lower.endswith("." + entry_l)
        if matches and len(entry_l) > len(best):
            best = entry_l
    return best


def _match_ip_cidr(ip: str, cidrs: list[str]) -> str:
    if not ip or ip == "-":
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in net:
            return cidr
    return ""


@lru_cache(maxsize=1)
def _load_intel() -> dict[str, Any]:
    """Load + cache the bundled static intel JSON."""
    resource = files("network_threat") / "data" / "intel_static.json"
    with resource.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"intel_static.json must be an object; got {type(data).__name__}")
    # Defensive defaults so downstream lookups never KeyError.
    data.setdefault("known_bad_domains", [])
    data.setdefault("known_bad_ip_cidrs", [])
    data.setdefault("tor_exit_node_cidrs", [])
    return data


# Constants used for sub-tagging (sourced from the bundled JSON's `notes`).
_DYNAMIC_DNS_SUFFIXES: frozenset[str] = frozenset(
    {
        "duckdns.org",
        "no-ip.com",
        "no-ip.org",
        "noip.com",
        "freedns.afraid.org",
        "ddns.net",
        "hopto.org",
        "zapto.org",
        "mooo.com",
    }
)

_URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "is.gd",
    }
)


__all__ = ["enrich_with_intel"]
