# Example 3 — ATT&CK technique observed (forward-looking)

**Input:** A MITRE ATT&CK STIX 2.1 bundle snapshot + (in future v0.x) a D.3 Runtime Threat workspace that surfaces process-evidence consistent with `T1059 Command and Scripting Interpreter`.

**Status in v0.1:** The technique-observation correlator path is **wired through the agent driver but not actively emitting findings in v0.1** — it needs D.3 v0.x evidence keys that map process events to ATT&CK technique IDs (`runtime_threat_finding.evidence.attack_technique`-shaped breadcrumbs). v0.1 ships the ATT&CK technique index in Stage 2 ENRICH (and optionally persists TechniqueEntities to the SemanticStore) so the correlator + Meta-Harness can light it up incrementally.

**What the emit will look like once D.3 ships the evidence breadcrumb (v0.x):**

```yaml
finding_type: threat_intel_attack_technique_observed
severity: MEDIUM # canonical (table-driven)
title: ATT&CK T1059 (Command and Scripting Interpreter) observed
finding_id: TI-TECHNIQUE-T1059-001-d3_run_<hash>
class_uid: 2004
evidence:
  technique_id: T1059
  technique_name: Command and Scripting Interpreter
  tactics: [execution]
  platforms: [Linux, Windows, macOS]
  source_d3_finding_id: RUNTIME-PROCESS-ABC123-001-spawn
```

**Markdown report row (per-severity section):**

> **Medium (1).**
>
> - `TI-TECHNIQUE-T1059-001-d3_run_<hash>` — ATT&CK T1059 (Command and Scripting Interpreter) observed
>   Type: threat_intel_attack_technique_observed

**Required attribution.** Every report ends with the MITRE ATT&CK® CC-BY-4.0 attribution footer. The footer also calls out NVD (public domain) + CISA KEV (CC0) for transparency.

**Why this example exists in v0.1 even though no findings emit:**

- It documents the wire shape so D.3 v0.x or Meta-Harness contributors can wire the evidence breadcrumb against a stable target.
- The Stage 2 ENRICH technique-index build (and optional SemanticStore persistence) IS exercised in v0.1 — every NLAH bundle smoke test verifies the technique-record path through `read_mitre_attack`.
- It reminds operators that the ATT&CK feed is consulted (and therefore the CC-BY-4.0 attribution footer is required) on every run, even when the technique-observation correlator emits zero findings.
