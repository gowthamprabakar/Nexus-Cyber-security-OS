# Example 03 — `claims.>` fabric publish

D.12 is the **first publisher** on the `claims.>` substrate (ADR-012). This example shows the on-the-wire payload format and how downstream agents will consume it in v0.2.

## The wire shape

Per the wire-format resolution in the D.12 v0.1 plan (Q1), `claims.>` payloads are the lightweight **`nexus_claim` envelope** (NOT OCSF). Future v0.2 may add an OCSF discriminator; v0.1 keeps the wire minimal:

```json
{
  "claim_id": "01J7M3X9Z1K8RPVQNH2T8DCMNO",
  "customer_id": "acme",
  "agent_id": "curiosity",
  "hypothesis": {
    "statement": "The eu-west-3 region has 42 assets but no findings recorded in any scan window.",
    "rationale": "F.3 Cloud Posture and D.5 Data Security have not surfaced any findings for assets in eu-west-3...",
    "probe_directive": {
      "target_agent": "data_security",
      "target_resource_arn": "arn:aws:s3:::eu-west-3-*",
      "target_finding_id": null,
      "action": "scan",
      "rationale_ref": "01J7M3X9Z1K8RPVQNH2T8DCMNO"
    },
    "cited_gap": {
      "region": "eu-west-3",
      "asset_count": 42,
      "days_since_last_finding": 0,
      "severity_hint": "medium"
    }
  },
  "emitted_at": "2026-05-21T08:00:08+00:00"
}
```

Note that `probe_directive.rationale_ref` equals `claim_id` — the driver backfills this after minting the ULID. Downstream consumers can join probe-directive → parent claim by this back-reference.

## NATS subject + stream

- **Stream:** `CLAIMS_STREAM` (`name="claims"`, retention 30 days, ordering per-tenant per-agent).
- **Subject:** `claims.tenant.acme.agent.curiosity` (per-tenant, per-emitting-agent).

A downstream consumer (e.g. D.7 Investigation v0.2) subscribes:

```python
# Hypothetical D.7 v0.2 consumer (NOT IMPLEMENTED in D.12 v0.1)
js_client = JetStreamClient(servers=[...], agent_id="investigation")
await js_client.connect()
await js_client.subscribe(
    CLAIMS_STREAM,
    "claims.tenant.acme.>",          # all claim emitters for this tenant
    on_claim_received,
    durable_name="d7-claims-consumer",
)
```

The `agent_id="investigation"` is allowed to subscribe to `claims.>` per ADR-012's subscriber-ACL fence. **A.1 Remediation is not** — its `agent_id="remediation"` is forbidden in `_FORBIDDEN_SUBSCRIPTIONS` because consuming speculative state in an auto-acting agent would risk remediating problems that aren't real.

## D.12 itself never subscribes

D.12 is producer-only on `claims.>`. The `claims_publisher` module wraps `JetStreamClient.publish`; D.12 does not call `subscribe` on this subject in v0.1. A future Curiosity-consumes-Curiosity loop (e.g. "did a prior hypothesis materialize into a real finding?") would land in v0.3+.

## Single-tenant `js_client=None` opt-in default

In v0.1, the agent driver's `js_client` parameter defaults to `None`. When unset (the v0.1 default), `publish_claims` logs `"claims_publisher.publish_claims skipped: js_client=None"` and returns 0. The `hypotheses.md` + `probe_directives.json` workspace artifacts are still emitted so the operator can review the run output without a live NATS broker.

Production wires a real `JetStreamClient` (constructed with `agent_id="curiosity"`) when NATS is available. The substrate's subscriber-ACL fence (ADR-012) still gates A.1 vs claims.> at every subscription attempt — D.12 doesn't have to enforce it.
