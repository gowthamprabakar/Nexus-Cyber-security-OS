"""WI-T4 (HARD) — live continuous-ingestion end-to-end (D.8 v0.2 Task 17).

Two-layer per the WI-V6 (D.1) / WI-I4 (D.2) standard:

1. **Offline layer (every push):** the real continuous-ingestion path — live readers +
   STIX/HTTP transports + the `ContinuousIngestor` + reconnect resilience — exercised
   end-to-end with injected fake transports (no network).
2. **Gated-live layer (`NEXUS_LIVE_THREAT_INTEL=1`):** actually polls the live feeds;
   skipped in CI via the `live_gate` fixture.

Honest scope (WI-T3): the live readers + framework are e2e-tested here through
normalization; wiring the live readers into the agent's correlation→OCSF *continuous*
run loop is a v0.3 carry-forward (the offline `run()` remains the OCSF-emitting path,
asserted byte-identical). The OCSF 2004 emission contract is exercised below by
building a finding from a live-read IOC.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from shared.fabric.envelope import NexusEnvelope
from threat_intel.continuous import ContinuousIngestor, SubscriptionManager
from threat_intel.live_lane import feeds_reachable, nexus_live_threat_intel_enabled
from threat_intel.schemas import (
    AffectedResource,
    Severity,
    ThreatIntelFindingType,
    build_finding,
)
from threat_intel.tools.abuse_ch import read_malwarebazaar, read_threatfox, read_urlhaus
from threat_intel.tools.kev_live import CisaKevLiveReader
from threat_intel.tools.mitre_live import MitreAttackLiveReader
from threat_intel.tools.nvd_live import NvdLiveReader
from threat_intel.tools.otx import read_otx
from threat_intel.tools.stix_taxii import TaxiiClient, TaxiiError

pytestmark = pytest.mark.asyncio


# --------------------------- fake transports -----------------------------


class _Http:
    """HttpTransport: get(url, headers) → (status, headers, body)."""

    def __init__(self, status: int, body: Any) -> None:
        self._s, self._b = status, body

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        return self._s, {}, self._b


class _Taxii:
    """TaxiiTransport: get(url, params, headers) → (status, body)."""

    def __init__(self, body: dict[str, Any]) -> None:
        self._b = body

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        return 200, self._b


def _nvd_body(cve_id: str) -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2026-06-01T00:00:00.000",
                    "lastModified": "2026-06-10T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "x"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }


# ------------------- offline layer: per-feed e2e -------------------------


async def test_nvd_live_e2e_offline() -> None:
    recs, cursor = await NvdLiveReader(_Http(200, _nvd_body("CVE-2026-0001"))).poll()
    assert [r.cve_id for r in recs] == ["CVE-2026-0001"]
    assert cursor == "2026-06-10T00:00:00"


async def test_kev_live_e2e_offline() -> None:
    body = {"vulnerabilities": [{"cveID": "CVE-2026-0002", "dateAdded": "2026-06-10"}]}
    entries, _ = await CisaKevLiveReader(_Http(200, body)).poll()
    assert [e.cve_id for e in entries] == ["CVE-2026-0002"]


async def test_mitre_live_e2e_offline() -> None:
    tech = {
        "type": "attack-pattern",
        "id": "attack-pattern--1",
        "name": "T",
        "modified": "2026-06-10T00:00:00.000Z",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
    }
    reader = MitreAttackLiveReader(
        TaxiiClient(_Taxii({"objects": [tech], "more": False})), collection_url="https://x/c"
    )
    techniques, _ = await reader.poll()
    assert [t.technique_id for t in techniques] == ["T1059"]


async def test_urlhaus_e2e_offline() -> None:
    iocs = await read_urlhaus(transport=_Http(200, {"urls": [{"url": "http://bad"}]}))
    assert iocs[0].value == "http://bad"


async def test_threatfox_e2e_offline() -> None:
    iocs = await read_threatfox(
        transport=_Http(200, {"data": [{"ioc": "1.2.3.4", "ioc_type": "ip"}]})
    )
    assert iocs[0].value == "1.2.3.4"


async def test_malwarebazaar_e2e_offline() -> None:
    iocs = await read_malwarebazaar(transport=_Http(200, {"data": [{"sha256_hash": "a" * 64}]}))
    assert iocs[0].value == "a" * 64


async def test_otx_e2e_offline() -> None:
    body = {"results": [{"name": "p", "indicators": [{"indicator": "9.9.9.9", "type": "IPv4"}]}]}
    iocs = await read_otx(transport=_Http(200, body), api_key="K")
    assert iocs[0].value == "9.9.9.9"


# ------------------- offline layer: ingestor + resilience ----------------


async def test_continuous_ingestor_multi_feed_e2e() -> None:
    collected: list[dict[str, Any]] = []

    async def handler(item: dict[str, Any]) -> None:
        collected.append(item)

    async def nvd_source() -> AsyncIterator[dict[str, Any]]:
        recs, _ = await NvdLiveReader(_Http(200, _nvd_body("CVE-2026-0003"))).poll()
        for r in recs:
            yield {"feed": "nvd", "id": r.cve_id}

    async def urlhaus_source() -> AsyncIterator[dict[str, Any]]:
        iocs = await read_urlhaus(transport=_Http(200, {"urls": [{"url": "http://evil"}]}))
        for i in iocs:
            yield {"feed": "urlhaus", "id": i.value}

    mgr = SubscriptionManager()
    mgr.register("nvd", nvd_source, handler)
    mgr.register("urlhaus", urlhaus_source, handler)
    stats = await ContinuousIngestor(mgr).run_until_drained()

    assert stats.ingested == 2 and stats.errors == 0
    assert {c["feed"] for c in collected} == {"nvd", "urlhaus"}


async def test_taxii_reconnect_resilience() -> None:
    calls = {"n": 0}

    class _FlakyTaxii:
        async def get(
            self,
            url: str,
            *,
            params: dict[str, str] | None = None,
            headers: dict[str, str] | None = None,
        ) -> tuple[int, dict[str, Any]]:
            calls["n"] += 1
            if calls["n"] < 2:
                raise ConnectionError("dropped")
            return 200, {"objects": [], "more": False}

    reader = MitreAttackLiveReader(
        TaxiiClient(_FlakyTaxii(), max_retries=3), collection_url="https://x/c"
    )
    techniques, _ = await reader.poll()
    assert techniques == () and calls["n"] == 2  # reconnected after one drop


async def test_taxii_unreachable_after_retries_raises() -> None:
    class _Dead:
        async def get(
            self,
            url: str,
            *,
            params: dict[str, str] | None = None,
            headers: dict[str, str] | None = None,
        ) -> tuple[int, dict[str, Any]]:
            raise ConnectionError("dropped")

    reader = MitreAttackLiveReader(
        TaxiiClient(_Dead(), max_retries=2), collection_url="https://x/c"
    )
    with pytest.raises(TaxiiError):
        await reader.poll()


async def test_nvd_dedup_across_polls_e2e() -> None:
    reader = NvdLiveReader(_Http(200, _nvd_body("CVE-2026-0004")))
    _, cursor = await reader.poll()
    # Second poll with the cursor: the same record (lastModified == cursor) is filtered.
    recs2, _ = await reader.poll(since=cursor)
    assert recs2 == ()


# ------------------- offline layer: OCSF 2004 emission -------------------


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d8d8",
        tenant_id="acme",
        agent_id="threat_intel",
        nlah_version="d8-v0.2",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


async def test_live_read_ioc_to_ocsf_2004_emission() -> None:
    # A live-read URLhaus IOC → an OCSF 2004 Detection Finding (the emission contract).
    iocs = await read_urlhaus(
        transport=_Http(200, {"urls": [{"url": "http://bad", "threat": "malware"}]})
    )
    finding = build_finding(
        finding_id="TI-IOC_NET-URLHAUS-001-bad",
        finding_type=ThreatIntelFindingType.IOC_MATCH_NETWORK,
        severity=Severity.HIGH,
        title=f"IOC {iocs[0].value}",
        description="live-read IOC",
        affected=[
            AffectedResource(
                cloud="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="workload",
                resource_id="i-0abc",
                arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
            )
        ],
        detected_at=datetime(2026, 6, 10, tzinfo=UTC),
        envelope=_envelope(),
    )
    assert finding.to_dict()["class_uid"] == 2004


# --------------------------- gated-live layer ----------------------------


async def test_live_feeds_reachable(live_gate: None) -> None:
    ok, reason = feeds_reachable()
    assert ok, f"live feeds unreachable: {reason}"


async def test_live_nvd_poll_e2e(live_gate: None) -> None:
    from threat_intel.tools.nvd_live import read_nvd_live

    records, cursor = await read_nvd_live()
    assert isinstance(records, tuple)  # live shape holds (content varies)
    assert cursor is None or isinstance(cursor, str)


async def test_lane_flag_is_reportable() -> None:
    # The offline layer runs regardless; the gated tests skip when the lane is off.
    assert nexus_live_threat_intel_enabled() in (True, False)
