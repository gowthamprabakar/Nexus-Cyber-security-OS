# Example 1 — C2 beacon detected

**Input:** A 1-hour window of VPC Flow Logs from `vpc-prod-east-1`.

**Observation:** One internal host (10.0.1.42) makes a connection to a Tor-exit-node IP (185.220.101.42) every 60s ± 0.4s for the entire hour. 60 connections; CoV = 0.007.

**Detection (deterministic, no LLM needed):**

```yaml
finding_type: network_beacon
severity: CRITICAL # count=60 >= 50 AND CoV=0.007 <= 0.10
title: Beacon from 10.0.1.42 to 185.220.101.42:443 — 60 hits, period 60.0s
detector_id: beacon@0.1.0
src_ip: 10.0.1.42
dst_ip: 185.220.101.42
evidence:
  connection_count: 60
  period_seconds: 60.001
  coefficient_of_variation: 0.007
  confidence: 0.997
```

**After ENRICH (Tor exit match):**

```yaml
evidence:
  intel:
    tags: ['known_bad', 'tor_exit']
    matched_ip_cidr: 185.220.101.0/24
# severity stays CRITICAL (already at ceiling)
```

**Markdown report pin (top of report, above per-section):**

> **CRITICAL beacon detected.** Host `10.0.1.42` is beaconing to a Tor exit node (`185.220.101.42:443`) every 60s for the last hour (60 hits, CoV 0.007). Recommend immediate review of `10.0.1.42`'s outbound policy + endpoint forensics.

**Operator next steps** (we do NOT take these autonomously in v0.1):

1. Pull endpoint EDR telemetry on `10.0.1.42` for the matching window.
2. Block 185.220.101.0/24 at the WAF (out-of-band; D.4 v0.1 does not block).
3. Hand off to D.7 Investigation Agent for cross-feed correlation.
