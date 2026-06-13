# Runbook — Multi-Tier Authorization (remediation v0.2)

A.1 has three tiers: `recommend` (default), `dry-run`, `execute`. **Execute is the only mutating
tier** and requires BOTH opt-in layers (H1/WI-A8, defense in depth):

1. **CLI kill-switch** — `--enable-execute` on `remediation run`.
2. **auth.yaml field** — `mode_execute_authorized: true`.

```yaml
# auth.yaml
mode_execute_authorized: true
authorized_actions: # H2 allowlist (action_type values)
  - remediation_k8s_patch_runAsNonRoot
  - remediation_k8s_patch_disable_privileged_container
privileged_actions_authorized: true # WI-A16 — EXTRA authz for privileged-container disable
max_actions_per_run: 5 # H5 blast radius (1-50; hard ceiling 50)
```

The invariants `assert_default_recommend` (H1) + `assert_action_allowlisted` (H2) +
`assert_privileged_action_extra_authz` (WI-A16) enforce these at the AUTHZ stage.
