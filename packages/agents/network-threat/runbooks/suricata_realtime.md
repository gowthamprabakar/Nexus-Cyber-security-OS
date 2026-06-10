# Runbook — Suricata Real-Time Feed (D.4 v0.2)

Live real-time Suricata eve.json subscription via a Unix socket.

## Setup

1. Configure Suricata to write eve.json to a socket:
   ```yaml
   # suricata.yaml
   outputs:
     - eve-log:
         enabled: yes
         filetype: unix_stream
         filename: /var/run/suricata/eve.sock
         types: [{ alert: {} }]
   ```
2. Ensure the agent can reach `/var/run/suricata/eve.sock`.

## Run (gated live)

```bash
NEXUS_LIVE_NETWORK_SURICATA=1 uv run pytest \
  packages/agents/network-threat/tests/integration/test_network_realtime_e2e.py -v -k suricata
```

## Notes

- Real-time runs **alongside** the heartbeat (offline `read_suricata_alerts`) — no preempt
  at v0.2 (Q1).
- Rule packs hot-reload without restarting the subscriber (`suricata/rule_packs.py`).
- The **only** action D.4 emits is a **TTL-bounded** IP block (Q4): public IPs only, TTL
  ≤ 1h, auto-expiring. Permanent blocks / BGP changes are the A.1 Remediation cycle.
