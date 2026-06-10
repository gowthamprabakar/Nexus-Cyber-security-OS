# Runbook — AWS VPC Flow Logs Live (D.4 v0.2)

Live AWS VPC Flow Logs via CloudWatch Logs. **AWS only at v0.2** (Azure NSG + GCP VPC → v0.3).

## Setup

1. Publish VPC Flow Logs to a CloudWatch Logs group (v2 default fields supported; custom
   v3/v4/v5 field orders pass via the `fields` parameter).
2. Grant the agent's AWS principal `logs:FilterLogEvents` on the flow-log group.
3. Configure credentials (the boto3 default chain or `AWS_PROFILE=<profile>`).

## Run (gated live)

```bash
AWS_PROFILE=dev NEXUS_LIVE_NETWORK_VPC_AWS=1 uv run pytest \
  packages/agents/network-threat/tests/integration/test_network_realtime_e2e.py -v -k vpc
```

## Notes

- The lane gates on `STS get_caller_identity` reachability through the charter
  CredentialResolver (Pattern A).
- Records parse byte-identical to the offline path; flows roll up by 4-tuple for the
  connection-rate (fan-out) anomaly detector.
- **Safety (Q4/WI-N8/WI-N10):** any emitted IP block is TTL-bounded (≤ 1h), public-IP-only,
  and auto-expiring — `assert_block_authorized` hard-rejects permanent / private-range /
  non-block actions; those are deferred to the A.1 Remediation cycle.
