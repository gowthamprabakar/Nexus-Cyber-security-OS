# Runbook — Live Remediation Lane (remediation v0.2, NEXUS_LIVE_REMEDIATION)

The v0.2 end-to-end lane drives the full 7-stage pipeline against a real `kind` cluster, exercising
all 7 action classes + execute + rollback + the 10 code-level invariants. CI skips it; operators
run it.

```bash
kind create cluster --name nexus-remediation-test
NEXUS_LIVE_REMEDIATION=1 uv run pytest \
  packages/agents/remediation/tests/integration/test_remediation_v0_2_e2e.py -v
```

The ungated portion of that file (all 7 action classes build + the full invariant chain + batched
safety) runs in CI on every PR — it proves the v0.2 surface composes without a cluster. The gated
portion proves the real apply/rollback. See also the v0.1 `NEXUS_LIVE_K8S` lane
(`test_agent_kind_live.py`).
