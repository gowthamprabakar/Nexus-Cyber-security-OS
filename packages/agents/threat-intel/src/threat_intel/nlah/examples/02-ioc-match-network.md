# Example 2 — IOC match against D.4 Network Threat finding

**Input:** A D.4 Network Threat workspace + an NVD CVE 2.0 snapshot covering `CVE-2021-44228`.

**Observation:** D.4's `findings.json` carries one Suricata alert (`class_uid 2004`, `finding_info.types[0] = network_suricata`) with evidence:

```yaml
src_ip: 10.0.1.42
dst_ip: 203.0.113.55
signature_id: 2034567
signature: 'ET EXPLOIT Possible CVE-2021-44228 exploit attempt'
```

The agent's Stage-2 ENRICH step has built the v0.1 IOC index from the NVD feed; `(IocType.CVE_ID, "CVE-2021-44228")` is in the index with confidence 0.6 (NVD-only) or 0.9 (if also KEV-listed).

**Observable extraction:** the correlator's regex catches `CVE-2021-44228` inside the Suricata `signature` string.

**Correlation (deterministic):**

```yaml
finding_type: threat_intel_ioc_match_network
severity: HIGH  # confidence 0.9 (KEV-listed) -> HIGH
title: IOC match: cve_id=CVE-2021-44228 in D.4 network finding
finding_id: TI-IOC_NET-CVE_ID_CVE-2021-44228-001-d4_net_<hash>
class_uid: 2004
evidence:
  ioc_entry:
    ioc_type: cve_id
    value: CVE-2021-44228
    confidence: 0.9
    source_feed: cisa_kev   # KEV wins on overlap with NVD
  source_d4_finding_id: NETWORK-SURICATA-10001042-001-sig
  observable_match:
    type: cve_id
    value: CVE-2021-44228
```

**Resource synthesis:** D.4's `affected_networks[0]` becomes a `network_endpoint` AffectedResource:

```yaml
resources:
  - type: network_endpoint
    uid: network:10.0.1.42:203.0.113.55
    region: n/a
```

**Markdown report (IOC matches section):**

> **IOC matches (1).**
>
> - `TI-IOC_NET-CVE_ID_CVE-2021-44228-001-d4_net_<hash>` — **HIGH** cve_id=`CVE-2021-44228` (in network)
>   → feed `cisa_kev` · confidence 0.9

**Within-finding dedup:** if Suricata's signature also mentioned `CVE-2021-44229`, that's a second observable; both would emit if both are in the IOC index. The correlator de-dupes per (ioc_type, value) within the same source D.4 finding so src_ip + evidence.src_ip aliases don't double-count.

**v0.2 forward-look:** abuse.ch + VirusTotal will populate IP/domain/URL/file-hash IOC types so the IOC-match-network surface grows substantially beyond CVE-IDs.
