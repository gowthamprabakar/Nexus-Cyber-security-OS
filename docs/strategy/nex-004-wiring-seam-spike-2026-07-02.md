# NEX-004 — Wiring-Seam Spike (the operating path) — SPIKE OUTPUT

**Timebox: 1 day. Deliverable: design + feed-gap list + firm impl tickets. NOT code.**

## The question

The #1 gap (from the deep analysis) is *tested ≠ operating*: detectors emit graph edges in e2e tests,
but a real `run()` doesn't build the moat. NEX-004 designs the **fixture-driven operating path** every
family wires into, so nothing new lands test-only.

## Finding: the pattern already exists — the risk is low

`nexus_runtime/correlation.py::correlation_run` already drives **real agent `run()`s**
(`data_security_run → identity_run → investigation_run`) against ONE shared `SemanticStore`, sequenced
(load-bearing order), with per-agent `ExecutionContract`s. It proves agent `run()`s populate a shared
graph. **The operating path is: extend this to (a) more agents and (b) emit `build_report_card` at the
end.** That last step is a ~5-line delta (`render_tenant_report_card(store, tenant)`), already built.

So the design is: **`operating_run(feeds, store) → each agent.run(feed, semantic_store=store) → build_report_card(store) → rendered card`**, with the sequence order preserved (writers before readers).

## Verified per-agent feed-gap list (the real work)

`run()` must accept a fixture feed so it runs offline (no cloud). Verified support:

| Agent | feed param in `run()`? | Wiring work |
|---|---|---|
| data-security | ✅ `s3_inventory_feed`, `s3_objects_feed` | none |
| cloud-posture | ✅ `fixtures` | none |
| vulnerability | ✅ `fixtures` | none |
| network-threat | ✅ `feed`/`feeds` | none |
| k8s-posture | ✅ `feed`/`feeds` | none |
| **identity** | ❌ only `semantic_store` (reads live IAM) | **004a: add an `iam_listing_feed`** |
| **appsec** | ❌ only `semantic_store` | **004b: add a `findings/secrets feed`** |

**So wiring is NOT one seam — it's the runner + 2 per-agent feed params.** (v3 critique #2, confirmed.)

## Firm impl tickets (created by this spike)

- **NEX-004a — identity `run()` fixture feed** (M): add `iam_listing_feed: Path|None`; when set, parse an
  `IdentityListing` from JSON instead of live IAM. Bank + e2e: fixture → `identity.run()` → graph has
  `CAN_ESCALATE_TO`/`HAS_ACCESS_TO`.
- **NEX-004b — appsec `run()` fixture feed** (M): add a leaked-creds/findings feed. Bank + e2e:
  fixture → `appsec.run()` → graph has `SECRET{leaked}`.
- **NEX-004c — `operating_run` + report card** (M): generalize `correlation_run` to N agents (order-safe)
  + emit `render_tenant_report_card`. e2e: multi-agent fixture → one call → the ranked card.
- **NEX-004d — wire the 10 built families' detectors into their agents' `run()`** (L, spread across S1–S3):
  each family's detector called in `run()` (like identity's escalation already is), gated on
  `semantic_store` present. **This is the dormancy fix — every family ticket in S1–S3 includes its own
  004d slice as DoD.**

## Estimate & sequencing

- 004a + 004b + 004c: Sprint 1 (the runner + the 2 feed gaps) — ~3 tickets.
- 004d: **folded into every family ticket** (S1–S3) as its run()-wiring DoD, not a separate big-bang.
- Risk: LOW — `correlation_run` de-risks the runner; feed params mirror existing agents.

## Decision

Adopt the operating-path design. **Wire-as-we-go via 004d is now a hard DoD line on every family
ticket** — no family lands test-only again. 004a/004b/004c scheduled into Sprint 1.
