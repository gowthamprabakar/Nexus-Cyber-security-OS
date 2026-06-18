# ADR-020 — AI-SPM (D.11) OCSF class mapping

**Status:** Accepted (2026-06-17) · **Cycle:** v0.4 Stage 2 (D.11 AI-SPM) · **Decides:** operator Q3.

## Context

D.11 AI-SPM has a locked dual scope: **(a) deployment discovery** (find AI/ML services +
assess their posture) and **(b) prompt-injection detection** (active Garak red-team against a
discovered endpoint). These are two different kinds of finding and must map to the right OCSF
v1.3 Findings-category (`category_uid 2`) class so downstream consumers (A.4 meta-harness,
SIEM) can discriminate them consistently with the rest of the fleet.

## Decision

D.11 emits **two** OCSF classes:

| Scope                              | OCSF class                  | Rationale                                                                                                                                                                                           |
| ---------------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| (a) deployment discovery / posture | **2003 Compliance Finding** | A misconfigured AI deployment (public endpoint, logging off, no guardrail, no CMK) is a _posture_ finding — identical kind to F.3/D.5/D.6/compliance/D.10. Carries a `compliance.control` block.    |
| (b) prompt-injection detection     | **2004 Detection Finding**  | A Garak probe that elicits injection/jailbreak behaviour is _an adversary technique succeeding against a model_ — a detection event, the same kind D.2/D.3/D.4 emit as 2004. No `compliance` block. |

Both classes:

- Are wrapped with the `NexusEnvelope` (ADR-004).
- Use `finding_id` `AISPM-<PROVIDER>-<NNN>-<context>` and the per-finding discriminator
  `finding_info.types[0]` (e.g. `aispm_sagemaker_endpoint_public`,
  `aispm_promptinjection_jailbreak`).
- Are built by `aispm.schemas.build_posture_finding` (2003) / `build_detection_finding` (2004).

## Consequences

- D.11 is the fleet's first dual-class emitter; the discriminator convention
  (`class_uid` + `finding_info.types[0]`) keeps the two streams cleanly separable.
- No schema/substrate change — both classes already exist in the OCSF taxonomy the fleet uses;
  the ADR-018 graph vocab (`AI_SERVICE`/`AI_MODEL` + edges) is already scaffolded, so the
  substrate **seal stays empty** for the D.11 cycle.
- Prompt-injection (2004) is produced only on the gated active-probe path
  (`NEXUS_LIVE_AISPM_PROBE`); the default offline run emits posture (2003) only.
