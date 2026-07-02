# Regression Lock — the green-path suite (NEX-002)

The 10 built attack-path families + the report card + convergence proofs. **This set must stay green
after every foundation / substrate / refactor ticket** in the 30-day pipe-hardening plan. A ticket that
reds any of these is not done.

Run it:

```bash
python -m pytest $(sed -n '/^- /s/^- //p' packages/integration/src/fleet_testkit/REGRESSION_LOCK.md | tr '\n' ' ') -q
```

## Locked tests (baseline: 16 passed, 2026-07-02)

- packages/integration/src/fleet_testkit/tests/test_full_moat_smoke.py
- packages/integration/src/fleet_testkit/tests/test_report_card_runner_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_escalation_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_azure_escalation_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_gcp_escalation_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_lateral_reach_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_pod_lateral_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_k8s_escape_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_leaked_cred_blast_radius_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_gcp_leaked_cred_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_azure_sp_leaked_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_stored_secret_e2e.py
- packages/integration/src/fleet_testkit/tests/test_path_cross_account_e2e.py

## Operator: wire this as a required CI check (I cannot merge).
