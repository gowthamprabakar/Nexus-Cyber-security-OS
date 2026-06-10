"""abuse.ch live feeds — URLhaus + ThreatFox + MalwareBazaar (D.8 v0.2 Task 8).

HTTP-polled (Q7, no TAXII) IOC feeds, each normalized to the internal `IocType`
vocabulary (URL / IP / DOMAIN / FILE_HASH) as an `AbuseChIoc`. Each reader is a
charter-registered tool that builds an httpx transport in production; tests inject a
fake transport. The real endpoints + query bodies are documented in the Task-21 runbook.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from threat_intel.schemas import IocType
from threat_intel.tools.http_poller import HttpTransport
from threat_intel.tools.nvd_live import _httpx_transport

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

#: ThreatFox ioc_type → internal IocType.
_THREATFOX_TYPE_MAP = {
    "ip:port": IocType.IP,
    "ip": IocType.IP,
    "domain": IocType.DOMAIN,
    "url": IocType.URL,
    "sha256_hash": IocType.FILE_HASH,
    "md5_hash": IocType.FILE_HASH,
    "sha1_hash": IocType.FILE_HASH,
}


class AbuseChReaderError(RuntimeError):
    """An abuse.ch feed request failed."""


@dataclass(frozen=True, slots=True)
class AbuseChIoc:
    """A normalized abuse.ch IOC."""

    ioc_type: IocType
    value: str
    threat: str
    source: str  # "urlhaus" / "threatfox" / "malwarebazaar"
    first_seen: str = ""


async def _get_json(transport: HttpTransport, url: str) -> Any:
    status, _headers, body = await transport.get(url, headers=None)
    if status >= 400:
        raise AbuseChReaderError(f"abuse.ch {url} returned HTTP {status}")
    return body


async def read_urlhaus(*, transport: HttpTransport | None = None) -> tuple[AbuseChIoc, ...]:
    """Recent malicious URLs from URLhaus → URL IOCs."""
    body = await _get_json(transport or _httpx_transport(), URLHAUS_URL)
    rows = body.get("urls", []) if isinstance(body, dict) else []
    out: list[AbuseChIoc] = []
    for u in rows:
        if not isinstance(u, dict):
            continue
        value = u.get("url")
        if not value:
            continue
        out.append(
            AbuseChIoc(
                ioc_type=IocType.URL,
                value=str(value),
                threat=str(u.get("threat", "")),
                source="urlhaus",
                first_seen=str(u.get("date_added", "")),
            )
        )
    return tuple(out)


async def read_threatfox(*, transport: HttpTransport | None = None) -> tuple[AbuseChIoc, ...]:
    """ThreatFox IOCs (ip / domain / url / hash) → normalized IOCs."""
    body = await _get_json(transport or _httpx_transport(), THREATFOX_URL)
    rows = body.get("data", []) if isinstance(body, dict) else []
    out: list[AbuseChIoc] = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        value = entry.get("ioc")
        ioc_type = _THREATFOX_TYPE_MAP.get(str(entry.get("ioc_type", "")))
        if not value or ioc_type is None:
            continue
        out.append(
            AbuseChIoc(
                ioc_type=ioc_type,
                value=str(value),
                threat=str(entry.get("threat_type", "")),
                source="threatfox",
                first_seen=str(entry.get("first_seen", "")),
            )
        )
    return tuple(out)


async def read_malwarebazaar(*, transport: HttpTransport | None = None) -> tuple[AbuseChIoc, ...]:
    """MalwareBazaar recent samples → FILE_HASH IOCs (sha256)."""
    body = await _get_json(transport or _httpx_transport(), MALWAREBAZAAR_URL)
    rows = body.get("data", []) if isinstance(body, dict) else []
    out: list[AbuseChIoc] = []
    for s in rows:
        if not isinstance(s, dict):
            continue
        value = s.get("sha256_hash")
        if not value:
            continue
        out.append(
            AbuseChIoc(
                ioc_type=IocType.FILE_HASH,
                value=str(value),
                threat=str(s.get("signature", "")),
                source="malwarebazaar",
                first_seen=str(s.get("first_seen", "")),
            )
        )
    return tuple(out)
