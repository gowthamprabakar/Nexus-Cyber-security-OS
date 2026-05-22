# Example 04 — Skill curation lifecycle (v0.2 Stages 6 + 7)

A walkthrough of the v0.2 SKILL_TRIGGER + SKILL_CREATE pipeline. Three routing paths are illustrated below: rejection on eval-gate failure, operator approval for a first-of-class skill, and auto-deploy for a refinement of an already-approved class.

## Setup

A.4 v0.2 is invoked with three new optional kwargs that opt into Stages 6 + 7:

- `llm_provider` — a `charter.llm.LLMProvider` (production: `AnthropicProvider`; tests: `FakeLLMProvider`).
- `audit_chain_loader` — `Callable[[agent_id: str], list[dict]]` that returns each agent's F.6 audit entries for the run.
- `eval_runner_loader` — `Callable[[agent_id: str], EvalRunner]` (production: resolves from the `nexus_eval_runners` entry-point group).

When any one of these is `None`, the lifecycle is skipped — A.4 runs as v0.1 (read-only diagnostics + report markdown only). The `skill_lifecycle` field of the resulting `MetaHarnessReport` is the empty `SkillLifecycleSummary()` default.

## Path A — eval-gate failure (candidate rejected)

```
Stage 6 SKILL_TRIGGER:
  audit_chain_loader("investigation") -> 5 tool-call entries, novel hash
  detect_skill_trigger(...) -> SkillTrigger(agent_id="investigation",
                                            tool_sequence_hash="ab12...",
                                            audit_entry_hashes=("h0", "h1", ...))

Stage 7 SKILL_CREATE:
  write_skill_candidate(...) -> SkillCandidate
    shadow_path = <workspace>/.nexus/candidate-skills/investigation/
                  iam-privesc/aws_iam_privesc_via_assumed_role/SKILL.md
  emit_skill_candidate_emitted(...)            # audit entry #1

  run_skill_eval_gate(...) -> EvalGateResult(passed=False,
                                             baseline_pass_rate=0.9,
                                             candidate_pass_rate=0.6,
                                             per_case_regressions=(("c3", 100.0),))
  emit_skill_eval_gate_completed(...)          # audit entry #2
  cache_eval_gate_result(...)                  # JSON beside the shadow

  # Eval-gate FAILED -> reject path
  reject_candidate(rejection_reason="eval-gate FAIL: per-case regression c3 dropped 100.0 pct")
    -> shadow SKILL.md removed; DeploymentDecision(deployed=False)
  emit_skill_rejected(...)                     # audit entry #3
```

`MetaHarnessReport.skill_lifecycle.deployments` carries one `DeploymentDecision(deployed=False, rejection_reason=...)`. The shadow file is gone; the cached `eval_gate_result.json` remains beside the (now-deleted) shadow for forensic recovery.

## Path B — first-of-class operator approval required

The same trigger fires for a new `(agent_id, category)` pair the operator has never approved.

```
Stage 7 SKILL_CREATE:
  ... candidate written + eval-gate runs + PASSES ...
  emit_skill_eval_gate_completed(...)  # audit entry #2

  decide_auto_deployable(...) -> None  # class not in registry
  write_candidate_notification(...)
    -> <workspace>/skill_candidate_iam-privesc__aws_iam_privesc_via_assumed_role.md
```

The markdown notification carries the skill_id, target_agent, category, shadow_path, eval-gate verdict, and the two CLI commands the operator runs:

```
meta-harness approve-skill iam-privesc/aws_iam_privesc_via_assumed_role
meta-harness reject-skill  iam-privesc/aws_iam_privesc_via_assumed_role --reason "<text>"
```

`MetaHarnessReport.skill_lifecycle.pending_operator_review` carries the skill_id; no deployment yet. The CLI flow is provided by Task 15 of v0.2 — `approve-skill` calls `approve_candidate(...)`, which promotes shadow → canonical, registers the class, and persists the updated `<workspace>/.nexus/skill-class-registry.json`.

## Path C — auto-deploy of a refinement

The operator already approved a skill under `(investigation, iam-privesc)` in a prior run. The class is registered. A new candidate fires for the same `(agent_id, category)` with a NEW `tool_sequence_hash`.

```
Stage 7 SKILL_CREATE:
  ... candidate written + eval-gate runs + PASSES ...

  decide_auto_deployable(...) -> SkillApprovalMode.AUTO_APPROVED  # class registered
  auto_deploy_candidate(...)
    -> shadow moved to canonical path:
       packages/agents/investigation/src/investigation/nlah/skills/
       iam-privesc/aws_iam_privesc_via_assumed_role_v2/SKILL.md
    -> deployment_status: CANDIDATE -> DEPLOYED (round-trip through skill_format)
    -> registry's deployed_skill_ids + deployed_tool_sequence_hashes extended
  emit_skill_deployed(...)             # audit entry #3
  save_skill_class_registry(...)
```

`MetaHarnessReport.skill_lifecycle.deployments` carries a `DeploymentDecision(deployed=True, approval_mode=AUTO_APPROVED, deployed_path=...)`. Every subsequent run of the target agent now loads this skill via `charter.nlah_loader.load_skill_metadata_index(skills_overlay=...)` once the agent is migrated to v0.2-aware NLAH loading.

## Safety gates exercised in every path

- **Q-ARCH-1 fence (ADR-012 §v1.1).** A.4 cannot subscribe to `claims.>`. Hypotheses can never be laundered into deployed procedural memory through this pipeline.
- **Q4 mandatory eval-gate.** No `--force` flag; no CLI bypass. A failed eval-gate ALWAYS routes to `reject_candidate`.
- **Q5 first-of-class.** New `(agent_id, category)` pairs require explicit operator approval via CLI; refinements within an approved class auto-deploy.
- **Trust-boundary overrides (Task 7).** `target_agent`, `created_by`, `deployment_status`, `eval_gate_status`, `provenance` are overridden post-parse — the LLM cannot misroute candidates, fabricate provenance, or claim a passed eval-gate it didn't earn.
- **WI-3 byte-equal probe.** Identical `SkillTrigger` + identical `FakeLLMProvider` response → identical `SKILL.md` bytes on disk across runs. Determinism is load-bearing for Task 15's stub-response fixtures and the Task 16 verification record.

## Backwards-compat regression probe

Invoking A.4 with no v0.2 lifecycle kwargs:

```python
report = await run(
    customer_id="acme",
    run_id="r_42",
    workspace_root=workspace,
)
assert report.skill_lifecycle == SkillLifecycleSummary()
```

The report shape is byte-equivalent to v0.1 except for the new (empty) `skill_lifecycle` field. Drift #5 (Task 1) locks this in.
