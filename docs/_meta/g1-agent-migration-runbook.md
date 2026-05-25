# G1 Agent Migration Runbook

How to enable effectiveness scoring for any Wave 1+ agent.

## What G1 effectiveness scoring measures

G1 (ADR-011) computes a composite effectiveness score for every deployed skill
across three axes: adoption, outcome, and feedback. The composite is
confidence-weighted — more data produces higher confidence. Scores are
persisted to workspace-scoped sidecar files and consumed by GEPA (v0.2.5+)
for prompt optimization.

An agent that emits **no** skill-lifecycle events will have `confidence=0.0`
with `reason="agent_not_emitting_events"` — GEPA naturally ignores
zero-confidence signals.

## The 2-line opt-in

Any agent using `charter.nlah_loader` v1.4+ (progressive-disclosure skill
loading) can opt into G1 scoring by adding two calls to its run lifecycle:

```python
from meta_harness.audit_emit import emit_skill_loaded, emit_skill_contributed

# At run start, after the skill is loaded:
emit_skill_loaded(
    audit_log=audit_log,
    skill_id=loaded_skill.skill_id,
    agent_id=self.agent_id,
    tenant_id=self.tenant_id,
)

# At run end, after the skill contributed to the outcome:
emit_skill_contributed(
    audit_log=audit_log,
    skill_id=loaded_skill.skill_id,
    agent_id=self.agent_id,
    tenant_id=self.tenant_id,
    outcome="success",  # "success", "failure", or "partial"
)
```

That's it. The meta-harness handles everything else: sidecar persistence,
axis computation, composite scoring, and storage.

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  Agent lifecycle              Meta-harness (G1)             │
│  ─────────────                ─────────────────             │
│                                                             │
│  emit_skill_loaded()  ───────▶ sidecar run-events.jsonl     │
│                               (agent.skill.loaded)          │
│                                       │                     │
│                                       ▼                     │
│  emit_skill_contributed() ───▶ sidecar run-events.jsonl     │
│                               (agent.skill.contributed)     │
│                                       │                     │
│                                       ▼                     │
│                               compute_adoption_metrics()    │
│                               compute_outcome_correlation() │
│                               compute_feedback_axis()       │
│                                       │                     │
│                                       ▼                     │
│                               compute_effectiveness_score() │
│                                       │                     │
│                                       ▼                     │
│                               effectiveness.json sidecar    │
│                                                             │
│  Operator rating ────────────▶ operator-ratings.jsonl       │
│  (Task 11 CLI)                (agent.skill.operator_rated)  │
└─────────────────────────────────────────────────────────────┘
```

## Where the helpers live

| Helper                   | Module                    | Purpose                                |
| ------------------------ | ------------------------- | -------------------------------------- |
| `emit_skill_loaded`      | `meta_harness.audit_emit` | Record skill activation at run start   |
| `emit_skill_contributed` | `meta_harness.audit_emit` | Record skill outcome at run end        |
| `emit_operator_rating`   | `meta_harness.audit_emit` | Record operator feedback (Task 11 CLI) |

All helpers are thin wrappers around `audit_log.append()` — they write to
the audit chain and the meta-harness sidecar projection layer handles
cross-run persistence automatically.

## How to verify activation

1. **Deploy the agent** and run it at least once with a skill loaded.

2. **Check sidecar files:**

   ```bash
   ls .nexus/deployed-skills/<agent_id>/<skill_id>/
   # Should contain: run-events.jsonl
   ```

3. **Check emission status** via the compat module:

   ```python
   from meta_harness.effectiveness_compat import detect_agent_emission_status
   status = detect_agent_emission_status(
       agent_id="my-agent",
       audit_log=audit_log,
       workspace_root=workspace_root,
   )
   assert status == AgentEmissionStatus.EMITTING
   ```

4. **Compute a score:**

   ```python
   from meta_harness.skill_effectiveness import compute_effectiveness_score
   score = compute_effectiveness_score(
       skill_id="my-skill",
       agent_id="my-agent",
       audit_log=audit_log,
       workspace_root=workspace_root,
   )
   print(f"Score: {score.global_score}, Confidence: {score.confidence}")
   ```

5. **Wait for data accumulation.** Adoption confidence reaches 1.0 at 10
   loads. Outcome confidence reaches 1.0 at 10 contributions. Feedback
   confidence reaches 1.0 at 5 operator ratings.

## Backwards compatibility

Agents built before G1 (Wave 0) that do not emit lifecycle events are
automatically handled by the backwards-compat layer:

```python
from meta_harness.effectiveness_compat import apply_backwards_compat_reason
score = apply_backwards_compat_reason(
    score, agent_id="legacy-agent",
    audit_log=audit_log, workspace_root=workspace_root,
)
# score.reason == "agent_not_emitting_events" if the agent never emitted
```

GEPA v0.2.5+ calls `apply_backwards_compat_reason` before consuming any
score, ensuring silent agents are correctly classified.

## Related documents

- [ADR-011](../../adr/011-g1-effectiveness-scoring.md) — G1 architecture decision
- [G1 plan doc](../../docs/superpowers/plans/2026-05-23-g1-effectiveness-scoring-plan.md) — full implementation plan
- [Task 10 compat module](../../packages/agents/meta-harness/src/meta_harness/effectiveness_compat.py) — backwards-compat handler
- [A.4 meta-harness v0.2 plan](../../docs/superpowers/plans/2026-05-23-phase-1-wave-build-plan.md) — Wave 1 build plan

## Wave 1 agent migration status

| Agent                  | Status  | Notes                                               |
| ---------------------- | ------- | --------------------------------------------------- |
| F.3 cloud-posture v0.2 | Planned | First non-A.4 agent; A.4 skill integration in scope |
| Others                 | TBD     | Per Path B breadth-first rule                       |

_Last updated: 2026-05-25_
