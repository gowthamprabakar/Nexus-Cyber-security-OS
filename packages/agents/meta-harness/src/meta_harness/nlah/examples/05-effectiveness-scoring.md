# Example 05 — G1 effectiveness scoring lifecycle (v0.2.5)

A walkthrough of the full G1 effectiveness-scoring pipeline: skill deployment, lifecycle event emission, composite scoring, and operator feedback. This example shows how A.4 measures whether deployed skills are actually working.

## Setup

A skill (`aws_s3_public_bucket_detection`) has been deployed to the Cloud Posture agent via the v0.2 pipeline (Stages 6 + 7). The skill is at:

```
packages/agents/cloud-posture/src/cloud_posture/nlah/skills/
  s3-misconfig/aws_s3_public_bucket_detection/SKILL.md
```

The Cloud Posture agent has been migrated to v0.2 G1-aware runtime (per the [G1 migration runbook](../../../../../../docs/_meta/g1-agent-migration-runbook.md)) — it calls `emit_skill_loaded` at run start and `emit_skill_contributed` at run end.

## Step 1 — Agent runs, emits lifecycle events

The Cloud Posture agent runs against a customer environment. At run start, after loading the skill:

```python
from meta_harness.audit_emit import emit_skill_loaded

emit_skill_loaded(
    audit_log=audit_log,
    skill_id="s3-misconfig/aws_s3_public_bucket_detection",
    agent_id="cloud_posture",
    tenant_id="acme",
)
```

This writes to `<workspace>/.nexus/deployed-skills/cloud_posture/s3-misconfig/aws_s3_public_bucket_detection/run-events.jsonl`:

```json
{
  "action": "agent.skill.loaded",
  "agent_id": "cloud_posture",
  "skill_id": "s3-misconfig/aws_s3_public_bucket_detection",
  "tenant_id": "acme",
  "run_id": "run_001",
  "loaded_at": "2026-05-25T12:00:00Z",
  "contributed_at": null
}
```

At run end, after the skill contributed to the outcome:

```python
from meta_harness.audit_emit import emit_skill_contributed

emit_skill_contributed(
    audit_log=audit_log,
    skill_id="s3-misconfig/aws_s3_public_bucket_detection",
    agent_id="cloud_posture",
    tenant_id="acme",
    outcome="success",
)
```

The sidecar now also contains:

```json
{
  "action": "agent.skill.contributed",
  "agent_id": "cloud_posture",
  "skill_id": "s3-misconfig/aws_s3_public_bucket_detection",
  "tenant_id": "acme",
  "run_id": "run_001",
  "outcome": "success",
  "contributed_at": "2026-05-25T12:05:00Z",
  "loaded_at": null
}
```

After 10 runs (all successful), the sidecar has 20 events (10 loaded + 10 contributed).

## Step 2 — Operator computes effectiveness score

The operator runs the CLI to compute a score:

```
$ meta-harness score-effectiveness --agent cloud_posture --workspace-root /opt/nexus/workspace

AGENT                          SKILL                                              SCORE    CONF  REASON
---------------------------------------------------------------------------------------------------------
cloud_posture                  s3-misconfig/aws_s3_public_bucket_detection        0.875   0.80  -
```

What happened:

1. `compute_effectiveness_score` reads the sidecar `run-events.jsonl`
2. Adoption axis: 10 loads → adoption confidence = 1.0 (saturated at 10), adoption score = 1.0
3. Outcome axis: 10 successes / 10 total → correlation_score = 1.0, confidence = 1.0
4. Feedback axis: no operator ratings yet → confidence = 0.0 (drops out of composite)
5. Composite: (0.25 × 1.0 × 1.0 + 0.35 × 1.0 × 1.0) / (0.25 × 1.0 + 0.35 × 1.0) = 1.0
6. Score written to `<workspace>/.nexus/deployed-skills/cloud_posture/s3-misconfig/aws_s3_public_bucket_detection/effectiveness.json`

The audit chain now contains:

```json
{"action":"agent.skill.outcome_correlated","payload":{"skill_id":"s3-misconfig/aws_s3_public_bucket_detection","agent_id":"cloud_posture","correlation_score":1.0,"confidence":1.0,"success_count":10,"failure_count":0,"partial_count":0,"computed_at":"2026-05-25T12:10:00Z"}}
{"action":"meta_harness.skill.effectiveness_updated","payload":{"skill_id":"s3-misconfig/aws_s3_public_bucket_detection","agent_id":"cloud_posture","new_global_score":1.0,"new_confidence":0.571,"old_global_score":null,"old_confidence":0.0}}
```

## Step 3 — Operator rates the skill

The operator has been using this skill for a week and finds it reliably catches S3 misconfigurations:

```
$ meta-harness rate-skill s3-misconfig/aws_s3_public_bucket_detection \
    --rating useful \
    --note "catches public bucket misconfigs reliably; low false positive rate" \
    --agent cloud_posture \
    --workspace-root /opt/nexus/workspace

rated s3-misconfig/aws_s3_public_bucket_detection as useful at 2026-05-25T12:15:00Z
note: catches public bucket misconfigs reliably; low false positive rate
```

This appends to the audit chain:

```json
{
  "action": "agent.skill.operator_rated",
  "payload": {
    "skill_id": "s3-misconfig/aws_s3_public_bucket_detection",
    "agent_id": "cloud_posture",
    "rating": "useful",
    "note": "catches public bucket misconfigs reliably; low false positive rate",
    "rated_by": "cli-operator",
    "rated_at": "2026-05-25T12:15:00Z"
  }
}
```

And to the sidecar projection at `<workspace>/.nexus/deployed-skills/cloud_posture/s3-misconfig/aws_s3_public_bucket_detection/operator-ratings.jsonl`.

After 5 operators rate the skill (all `useful`), the feedback axis confidence reaches 1.0.

## Step 4 — Full composite score

With all three axes now having data, the operator re-runs the scoring:

```
$ meta-harness score-effectiveness --agent cloud_posture --skill s3-misconfig/aws_s3_public_bucket_detection --workspace-root /opt/nexus/workspace

AGENT                          SKILL                                              SCORE    CONF  REASON
---------------------------------------------------------------------------------------------------------
cloud_posture                  s3-misconfig/aws_s3_public_bucket_detection        0.912   1.00  -
```

Composite breakdown:

- Adoption: score=1.0, confidence=1.0, weight=0.25
- Outcome: score=1.0, confidence=1.0, weight=0.35
- Feedback: score=0.833, confidence=1.0, weight=0.40
- Composite: (0.25×1.0×1.0 + 0.35×1.0×1.0 + 0.40×0.833×1.0) / (0.25×1.0 + 0.35×1.0 + 0.40×1.0) = 0.912

The audit chain now contains a second `effectiveness_updated` event (score changed from 1.0 → 0.912 as the feedback axis joined the composite):

```json
{
  "action": "meta_harness.skill.effectiveness_updated",
  "payload": {
    "skill_id": "s3-misconfig/aws_s3_public_bucket_detection",
    "agent_id": "cloud_posture",
    "new_global_score": 0.912,
    "new_confidence": 1.0,
    "old_global_score": 1.0,
    "old_confidence": 0.571
  }
}
```

## Step 5 — GEPA consumes the score

GEPA v0.2.5 reads `effectiveness.json` and passes `global_score` as the `metric=` callable input for prompt optimisation:

```python
from meta_harness.effectiveness_store import get_effectiveness_score

score = get_effectiveness_score(
    "s3-misconfig/aws_s3_public_bucket_detection",
    "cloud_posture",
    workspace_root=workspace_root,
)
assert score is not None
assert score.global_score == 0.912  # feeds into GEPA metric= callable
```

Skills with higher effectiveness scores get more optimisation budget. Zero-confidence skills (new or non-emitting agents) are naturally ignored — GEPA skips `confidence=0.0` signals.

## Safety gates exercised

- **CF #2 fix-pattern.** If `compute_effectiveness_score` encounters a malformed sidecar record, it emits `meta_harness.skill.effectiveness_error` with `error_type="unknown_outcome_value"` and skips the record — the computation continues with valid records. A fatal sidecar read failure re-raises after emitting the error.
- **Idempotent score writes.** Running `score-effectiveness` twice with no new events produces no duplicate `effectiveness_updated` audit entry — `write_effectiveness_score` compares `global_score` + `confidence` against the existing sidecar score before emitting.
- **Backwards-compat.** A Wave 0 agent that has never emitted lifecycle events gets `confidence=0.0` with `reason="agent_not_emitting_events"` — GEPA naturally ignores it. The `apply_backwards_compat_reason` function in `effectiveness_compat` handles this automatically.
- **Confidence gating.** Axes with zero confidence drop out of the composite numerator and denominator. A skill with only adoption data (no contributed events, no operator ratings) still gets a score — but from adoption alone, weighted at 0.25.
- **Tenant isolation.** Sidecar paths are scoped by tenant. `score-effectiveness --tenant acme` reads only `acme`'s events; `score-effectiveness --tenant default` reads `default`'s. Cross-tenant leakage is prevented by the path structure.

## Audit-chain trace for the full lifecycle

After Steps 1–4, the audit chain contains a complete, verifiable trace:

1. `agent.skill.loaded` → sidecar (agent-emitted, run start)
2. `agent.skill.contributed` → sidecar (agent-emitted, run end)
3. `agent.skill.outcome_correlated` → audit chain (A.4 computed outcome axis)
4. `meta_harness.skill.effectiveness_updated` → audit chain (score persisted)
5. `agent.skill.operator_rated` → audit chain + sidecar (operator feedback)
6. `meta_harness.skill.effectiveness_updated` → audit chain (score changed after feedback)

Every audit-chain entry carries full hash-chain linkage (Task 3). A downstream compliance agent (D.6) walking the chain can reconstruct the full scoring history from these entries — when each axis was computed, who rated the skill and why, and how the composite score evolved over time.
