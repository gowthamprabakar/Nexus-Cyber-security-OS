# Runbook — Tamper Response (audit v0.2)

## Detect

`audit.tamper.detect.detect_tampering(events)` returns every break categorized:
`genesis_violation` / `missing_entry` / `hash_mismatch` / `timestamp_skew`.

## Alert

`audit.tamper.alert.emit_tamper_alerts(chain_id, events)` emits an OCSF 6003 alert per finding,
carrying `broken_chain_id`, `last_valid_entry`, `suspected_tamper_point`, `tamper_category`.
A break ALWAYS surfaces an alert (WI-F9).

## DO NOT repair

F.6 NEVER repairs a chain (WI-F2 architectural invariant — v0.3 doesn't get repair either).
Preserve the tampered chain as forensic evidence; investigate via D.7 / A.1 out of band.
