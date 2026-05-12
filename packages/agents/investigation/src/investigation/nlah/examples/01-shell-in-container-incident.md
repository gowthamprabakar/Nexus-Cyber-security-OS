# Example: shell-in-container incident investigation

D.3 Runtime Threat surfaces a CRITICAL Falco alert: `Terminal shell in container` on `pod=frontend-7f9d, namespace=production, container.id=abc123`. Supervisor delegates to D.7 with the incident contract.

D.7's response:

1. **SCOPE** — derive `tenant_id` from contract, `since = alert_time - 1h`, `until = alert_time + 30min`, seed entity = the container.
2. **SPAWN** four sub-investigations in parallel under the agent's Charter:
   - `timeline` — pulls audit events + sibling findings.json from `runtime_threat/<run>` and `cloud_posture/<run>`.
   - `ioc_pivot` — runs `extract_iocs` over the timeline. Finds `192.0.2.42` outbound IP + a SHA-256 hash in the command line.
   - `asset_enum` — walks F.5 SemanticStore from the container entity. Finds the host, the service account, the parent deployment.
   - `attribution` — runs `map_to_mitre`. Top hit: T1059 Command and Scripting Interpreter (3 keyword matches on "shell" / "/bin/sh" / "shell spawn").
3. **SYNTHESIZE** — calls `charter.llm_adapter` with the collected events + asks for hypotheses in the documented JSON shape. LLM returns one hypothesis: "Attacker exploited CVE-2024-XXXX in the frontend service, spawned a shell to enumerate the cluster, then made an outbound C2 callback to 192.0.2.42." Confidence 0.8, evidence_refs covering the Falco alert + the IOC + the host entity.
4. **VALIDATE** — each evidence_ref resolves (audit_event found, finding found, entity found). Hypothesis stays.
5. **PLAN** — containment: rotate the service account's IAM creds, isolate the host from outbound network, snapshot the container for forensics. Eradication: kill the shell process, redeploy the frontend with patched image. Recovery: verify no other pods exhibit the same network signature for 24h.
6. **HANDOFF** — writes `incident_report.json` (OCSF 2005), `timeline.json` (4 events), `hypotheses.md`, `containment_plan.yaml`. Returns the IncidentReport to Supervisor.
