# Runbook — Rollback Testing (remediation v0.2)

H4 (`assert_rollback_on_failed_validation`) makes rollback **mandatory** when post-execute
validation fails: after execute, A.1 waits `rollback_window_sec`, re-runs the source detector, and
auto-applies the inverse patch if the rule still fires.

To test the rollback path against a real cluster (the `NEXUS_LIVE_K8S` / `NEXUS_LIVE_REMEDIATION`
lanes):

1. Deploy a workload violating a rule (e.g. `runAsUser: 0`).
2. Install a mutating admission webhook that strips the fix on apply (forces validation to fail).
3. Run `remediation run --mode execute --enable-execute`.
4. Expect outcome `executed_rolled_back` — the inverse patch reverts the workload, and H4's guard
   confirms the rollback actually ran.

See `tests/integration/test_agent_kind_live.py` +
`tests/integration/test_remediation_v0_2_e2e.py`.
