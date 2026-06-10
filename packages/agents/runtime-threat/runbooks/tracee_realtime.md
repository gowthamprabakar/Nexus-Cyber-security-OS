# Runbook — Tracee Real-Time Feed (D.3 v0.2)

Live real-time Tracee kernel-event subscription via its event pipe.

## Setup

1. Run Tracee streaming events (JSON) to its pipe/socket — e.g.:
   ```bash
   tracee --output json --output option:parse-arguments \
     --capture write --server.grpc --server.grpc.address unix:/var/run/tracee/tracee.sock
   ```
2. Ensure the agent can reach the socket at `/var/run/tracee/tracee.sock`.
3. eBPF requires a compatible kernel + `CAP_BPF` (or privileged) — confirm before enabling.

## Run (gated live)

```bash
NEXUS_LIVE_RUNTIME_TRACEE=1 uv run pytest \
  packages/agents/runtime-threat/tests/integration/test_runtime_realtime_e2e.py -v -k tracee
```

## Notes

- The Tracee lane is **separate** from the Falco lane (Q2 — independent gates).
- Live events normalize to the same `TraceeAlert` shape as the offline path, plus a
  syscall context (pathname / flags / return value).
- Falco + Tracee events on the same `(container, pid)` are correlated + de-duplicated.
- Tetragon advanced kernel telemetry is **v0.3** (Q2).
