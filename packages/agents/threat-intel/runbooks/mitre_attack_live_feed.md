# Runbook — MITRE ATT&CK Live Feed (D.8 v0.2)

Live TAXII 2.1 subscription to the MITRE ATT&CK **Enterprise** collection.

## Setup

1. Ensure outbound HTTPS to `attack-taxii.mitre.org`.
2. Confirm the Enterprise collection URL in `tools/mitre_live.py`
   (`MITRE_ENTERPRISE_COLLECTION_URL`) against the current MITRE TAXII server — MITRE
   has migrated servers historically; update the constant if the collection UUID moved.

## Run (gated live)

```bash
NEXUS_LIVE_THREAT_INTEL=1 uv run pytest \
  packages/agents/threat-intel/tests/integration/test_continuous_ingestion_e2e.py -v -k mitre
```

## Notes

- TAXII pagination (`more`/`next`) is followed automatically; resume with the `modified`
  cursor (`added_after`). Reconnect-on-failure is built in (WI-T9).
- **Licence:** MITRE ATT&CK is CC-BY-4.0 — the attribution footer in `report.md` is
  unchanged from v0.1 (H4).
- v0.2 parses `attack-pattern` techniques + `intrusion-set` `uses` edges; Mobile/ICS
  matrices + the deeper relationship graph are v0.3.
