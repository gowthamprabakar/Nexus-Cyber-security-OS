"""IOC index shared by D.8 v0.1 Tasks 8 (network) and 9 (runtime) correlators.

Built once per agent run during Stage 2 ENRICH and passed by reference
to each IOC-joining correlator. Keyed by ``(IocType, value)`` so the
same string under different IOC kinds (e.g., ``ip:1.2.3.4`` vs
``url:1.2.3.4``) gets distinct entries.

**v0.1 source population.** The three v0.1 feeds (NVD CVE / CISA KEV /
MITRE ATT&CK) carry CVE IDs natively; they do **not** carry IP /
domain / URL / file-hash IOCs. v0.1's IOC index is therefore sparse --
populated primarily with ``IocType.CVE_ID`` entries derived from
NVD + KEV. v0.2 plugs in IP / domain / URL feeds (abuse.ch /
VirusTotal); the index shape is forward-compatible.

The correlators (8 / 9) MUST tolerate a sparse v0.1 index without
breakage -- the no-match return-empty-tuple paths are exercised by
unit tests + by eval case 008 ``partial_workspace_presence``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from threat_intel.entities import IocEntity
from threat_intel.schemas import IocType

# (IocType, value) -> IocEntity. Mapping so the correlators can accept
# both built dicts and read-only views.
type IocIndex = Mapping[tuple[IocType, str], IocEntity]


def build_ioc_index(entries: Iterable[IocEntity]) -> dict[tuple[IocType, str], IocEntity]:
    """Index an iterable of ``IocEntity``s by ``(ioc_type, value)``.

    If the iterable contains duplicate ``(ioc_type, value)`` keys, the
    last one wins -- v0.1 assumes feed inputs already collapse per-IOC
    to one canonical entry (the Stage-2 ENRICH builder is the right
    place to merge duplicates, not the index).
    """
    return {(e.ioc_type, e.value): e for e in entries}


__all__ = ["IocIndex", "build_ioc_index"]
