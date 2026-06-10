# Runbook — Falco Real-Time Feed (D.3 v0.2)

Live real-time Falco event subscription via the gRPC outputs service.

## Setup

1. Run Falco with the **gRPC outputs** service enabled (unix socket):
   ```yaml
   # falco.yaml
   grpc:
     enabled: true
     bind_address: 'unix:///run/falco/falco.sock'
   grpc_output:
     enabled: true
   ```
2. Ensure the agent can reach the socket at `/run/falco/falco.sock`.

## Run (gated live)

```bash
NEXUS_LIVE_RUNTIME_FALCO=1 uv run pytest \
  packages/agents/runtime-threat/tests/integration/test_runtime_realtime_e2e.py -v -k falco
```

## Notes

- Real-time runs **alongside** the heartbeat (offline `falco_alerts_read`) — it does not
  preempt it at v0.2 (Q1; preempt is v0.3).
- Rule packs hot-reload without restarting the subscriber (`falco/rule_packs.py`).
- The **only** action D.3 emits is a read-only forensic **snapshot** (Q4); process
  kill / workload quarantine are deferred to the A.1 Remediation cycle.
