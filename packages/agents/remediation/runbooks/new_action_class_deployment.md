# Runbook — Deploying a New Action Class (remediation v0.2)

v0.2 added two action classes (privileged-container + auto-mount-sa-token). To add another:

1. **Enum** — add a `RemediationActionType` member in `schemas.py` (an action id, not a secret —
   add `# noqa: S105` if the name trips the ruff S105 check).
2. **Builder** — a new `action_classes/k8s_<name>.py` with `build_<name>(finding)` returning a
   `RemediationArtifact` (patch_body + inverse_patch_body + finding-derived correlation_id). Use
   `wrap_container_patch` (container-level) or `wrap_pod_spec_patch` (pod-spec-level).
3. **Registry** — wire `rule_id -> ActionClass(action_type, build, swap_for_inverse)` into
   `ACTION_CLASS_REGISTRY`.
4. **Source mapping** — add the rule_id to the relevant source(s) in `tools/source_mapping.py`.
5. **Extra authz** — if the action is high-blast-radius, add it to `PRIVILEGED_ACTIONS` (WI-A16)
   or write a bespoke validation invariant (cf. auto-mount WI-A17).
6. **Counts** — bump the `RemediationActionType` count + promotion-init + registry-keys tests.

host-network / host-pid / host-ipc are the next candidates (deferred from v0.2 — too high blast
radius; they require additional isolation-aware safety layers).
