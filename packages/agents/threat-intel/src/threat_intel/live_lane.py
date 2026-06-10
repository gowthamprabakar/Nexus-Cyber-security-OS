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
