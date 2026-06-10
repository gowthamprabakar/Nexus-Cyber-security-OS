"""NEXUS_LIVE_THREAT_INTEL gated live-eval lane (D.8 v0.2 Task 15).

Consumes the hoisted charter Pattern D (`charter.live_lane`). A **single** lane gates
all D.8 live feeds (WI-T1 keeps coverage measured per-feed, but they share one switch).
Reports whether the lane is enabled, per-feed reachability, and the `pytest.skip`
message with setup steps. A DISTINCT gate from F.3/D.1/D.2 lanes — D.8 owns its own.
"""

from __future__ import annotations

from collections.abc import Callable

from charter.live_lane import live_skip_reason, nexus_live_enabled

from threat_intel.tools.abuse_ch import MALWAREBAZAAR_URL, THREATFOX_URL, URLHAUS_URL
from threat_intel.tools.kev_live import KEV_URL
from threat_intel.tools.mitre_live import MITRE_ENTERPRISE_COLLECTION_URL
from threat_intel.tools.nvd_live import NVD_API_URL
from threat_intel.tools.otx import OTX_SUBSCRIBED_URL

THREAT_INTEL_LIVE_ENV = "NEXUS_LIVE_THREAT_INTEL"

#: All feeds the single lane covers (per-feed reachability, WI-T1).
FEED_ENDPOINTS: dict[str, str] = {
    "nvd": NVD_API_URL,
    "kev": KEV_URL,
    "mitre": MITRE_ENTERPRISE_COLLECTION_URL,
    "urlhaus": URLHAUS_URL,
    "threatfox": THREATFOX_URL,
    "malwarebazaar": MALWAREBAZAAR_URL,
    "otx": OTX_SUBSCRIBED_URL,
}

THREAT_INTEL_LIVE_SETUP = (
    "set NEXUS_LIVE_THREAT_INTEL=1 and ensure outbound HTTPS to the live CTI feeds "
    "(NVD / CISA KEV / MITRE TAXII / abuse.ch / OTX); set NVD_API_KEY + OTX_API_KEY "
    "for the authenticated feeds. e.g.: NEXUS_LIVE_THREAT_INTEL=1 uv run pytest "
    "packages/agents/threat-intel/tests/integration/test_continuous_ingestion_e2e.py -v"
)


def nexus_live_threat_intel_enabled() -> bool:
    """True iff D.8's live lane is enabled (`NEXUS_LIVE_THREAT_INTEL=1`)."""
    return nexus_live_enabled(THREAT_INTEL_LIVE_ENV)


def _probe_one(url: str) -> tuple[bool, str]:
    try:
        import httpx

        with httpx.Client(timeout=15.0) as client:
            resp = client.head(url, follow_redirects=True)
        return (resp.status_code < 500), "" if resp.status_code < 500 else f"HTTP{resp.status_code}"
    except Exception as exc:
        return False, type(exc).__name__


def feeds_reachable(
    probe_one: Callable[[str], tuple[bool, str]] = _probe_one,
) -> tuple[bool, str]:
    """Probe every feed endpoint. Returns ``(True, "")`` if all reachable, else
    ``(False, "<feed>:<reason>")`` for the first unreachable feed (secret-free)."""
    for feed, url in FEED_ENDPOINTS.items():
        ok, reason = probe_one(url)
        if not ok:
            return False, f"{feed}:{reason}"
    return True, ""


def threat_intel_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = feeds_reachable,
) -> str | None:
    """`None` when the lane is enabled AND all feeds reachable; otherwise the
    `pytest.skip` message with copy-paste setup instructions."""
    return live_skip_reason(
        THREAT_INTEL_LIVE_ENV, "threat-intel feeds", THREAT_INTEL_LIVE_SETUP, probe
    )


# ---------------------------------------------------------------------------
# Industry-vertical lane (Task 16) — a STUB establishing the lane shape for v0.3.
# The industry-grade feeds (Wiz Cloud Threat Landscape, Unit42) land in v0.3 per Q2;
# at v0.2 this lane always skips with a v0.3 note even when enabled.
# ---------------------------------------------------------------------------

THREAT_INTEL_INDUSTRY_LIVE_ENV = "NEXUS_LIVE_THREAT_INTEL_INDUSTRY"

#: Industry-grade feeds deferred to v0.3 (Q2) — placeholders that fix the lane shape.
INDUSTRY_FEEDS_V0_3: tuple[str, ...] = ("wiz-cloud-threat-landscape", "unit42")

THREAT_INTEL_INDUSTRY_LIVE_SETUP = (
    "set NEXUS_LIVE_THREAT_INTEL_INDUSTRY=1 once the industry-grade feeds land — Wiz "
    "Cloud Threat Landscape + Unit42 are v0.3 (Q2). This lane is a v0.2 stub: it fixes "
    "the env-gate + reachability shape so v0.3 only has to wire the feed clients."
)


def nexus_live_threat_intel_industry_enabled() -> bool:
    """True iff the industry-vertical lane is enabled (`NEXUS_LIVE_THREAT_INTEL_INDUSTRY=1`)."""
    return nexus_live_enabled(THREAT_INTEL_INDUSTRY_LIVE_ENV)


def industry_feeds_reachable() -> tuple[bool, str]:
    """v0.2 stub: there are no industry feeds yet, so this always reports unreachable
    with a v0.3 reason — the lane never runs until v0.3 wires Wiz Landscape + Unit42."""
    return False, "industry-feeds-are-v0.3"


def threat_intel_industry_live_skip_reason(
    probe: Callable[[], tuple[bool, str]] = industry_feeds_reachable,
) -> str | None:
    """Always returns a `pytest.skip` message at v0.2 — when disabled, the setup note;
    when enabled, the 'industry feeds are v0.3' reason (the stub probe is unreachable)."""
    return live_skip_reason(
        THREAT_INTEL_INDUSTRY_LIVE_ENV,
        "industry-vertical feeds",
        THREAT_INTEL_INDUSTRY_LIVE_SETUP,
        probe,
    )
