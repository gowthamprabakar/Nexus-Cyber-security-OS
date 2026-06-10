# Runbook — Zeek Real-Time Feed (D.4 v0.2)

Live real-time Zeek conn.log + dns.log subscription via the Broker API / a log socket.

## Setup

1. Run Zeek streaming logs over the Broker socket (or a JSON-streaming sink):
   ```
   # local.zeek — enable JSON streaming + Broker
   @load policy/tuning/json-logs.zeek
   redef Broker::default_listen_address = "127.0.0.1";
   ```
2. Ensure the agent can reach `/var/run/zeek/broker.sock`.

## Run (gated live)

```bash
NEXUS_LIVE_NETWORK_ZEEK=1 uv run pytest \
  packages/agents/network-threat/tests/integration/test_network_realtime_e2e.py -v -k zeek
```

## Notes

- The Zeek lane is **separate** from the Suricata lane (Q2 — independent gates).
- `conn` records normalize to `ZeekConn`; `dns` records normalize to the same `DnsEvent`
  the offline DNS reader produces.
- Zeek + Suricata events on the same connection 4-tuple are correlated + de-duplicated.
- Zeek log types beyond conn + dns are v0.3.
