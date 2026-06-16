# v0.4 Stage 1.4 — D.4 Network-threat Zeek-conn wiring + network topology — brainstorm

**Status:** brainstorm for operator review (per-PR review). Template locked at #712 + §9/§10.
**Directive:** `v0-4-directive-2026-06-16.md` §3 Stage 1.4 + Option X. **Catalogue:** #711 "C.x Network".
**Agent:** `packages/agents/network-threat`. **Discipline:** depth-first; per-agent ownership; seal EMPTY; live gated; offline byte-identical.

## 1. Current state (recon vs main `fec57f8`)

| Capability              | State                                                                                                      | Evidence                                        |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Zeek-conn normalizer    | **exists** (`normalize_zeek_conn` + `ZeekConn`) but **NOT wired to the live lane** (deferred Q4 follow-up) | `tools/zeek_normalize.py:48-66`; `agent.py:306` |
| FlowRecord              | exists (VPC-flow v5 schema)                                                                                | `schemas.py:137-163`                            |
| Readers                 | Suricata, Zeek-DNS (live), VPC-flow (live)                                                                 | `tools/{suricata,zeek,vpc_flow}*`               |
| kg_writer.py            | **absent**                                                                                                 | —                                               |
| Topology / reachability | **none** (flow-event detection only; no graph model)                                                       | —                                               |
| run() output            | OCSF **2004**; `findings.json` + `report.md` + `ip_block_actions.json`                                     | `agent.py`                                      |

**Net-new:** wire Zeek-conn into the live lane (→ FlowRecord) · network topology / reachability discovery · `kg_writer.py`.

## 2. Goal + scope boundary

- **Goal:** Zeek-conn flows drive the live lane; network flow + reachability written to the SemanticStore.
- **Covers:** Zeek-conn live wiring; flow-event inventory (L6); kg_writer.
- **⚠️ SCOPE QUESTION (surface):** the catalogue's "C.x Network" also owns **computed reachability edges** (`CAN_REACH`, `EXPOSED_TO`, `LATERAL_PATH`) derived over **D.3/D.5 security-group + NACL + route-table** config. network-threat today is a _flow-event detection_ agent (OCSF 2004), NOT a reachability-computation engine, and reachability needs D.3/D.5 network-config nodes as input. **Decision needed:** does v0.4 Stage 1.4 (a) wire Zeek-conn + flow inventory only (rec — bounded, matches the agent's nature), with reachability-edge computation a Stage 3 / later capability that reads the graph; or (b) build reachability computation now (larger; depends on D.3 network inventory landing first)?

## 3. Approach — per component (options + rec)

- **3a Zeek-conn live wiring.** Wire `normalize_zeek_conn` into the bounded-drain live lane (mirror Zeek-DNS); emit `FlowRecord`/network-flow events. Self-merge; offline byte-identical (default OFF).
- **3b Flow-event inventory + kg_writer.** New `kg_writer.py` (copy-pattern) writing **Network flow event nodes (L6)** (catalogue C.x Network) + `COMMUNICATES_WITH` (observed). Reachability edges (`CAN_REACH`/`EXPOSED_TO`) = **rec defer to the §2 decision** — if (a), these are computed in Stage 3 over the merged graph (network config from D.3 + flows from here), not in this agent.
- **3c Topology discovery.** Observed-communication topology from flows (L6); computed reachability (L4) gated on the §2 decision.

## 4. Sub-PR breakdown (self-merge cascade)

1. PR1 Zeek-conn live-lane wiring (→ FlowRecord; gated; offline byte-identical).
2. PR2 `kg_writer.py` + network-flow-event node schema + `COMMUNICATES_WITH` edges.
3. PR3 (conditional on §2 decision (b)) reachability computation (`CAN_REACH`/`EXPOSED_TO`) over D.3/D.5 network config — _only if operator picks (b)_.
4. PR4 cycle verification + coverage doc.

## 5. Substrate, invariants, gates

- Seal EMPTY (per-agent kg*writer). TTL-bounded IP-block safety (existing `assert_block_authorized`) preserved. Live behind `NEXUS_LIVE_NETWORK*\*`; offline byte-identical. Self-merge; Layer 27 before signal.

## 6. Coverage + honest limitations

- Coverage `[estimate]`. Zeek-conn wiring + flow inventory. **Honest:** computed reachability (the high-value `CAN_REACH`/`EXPOSED_TO` lateral-movement layer) is the bigger lever and is gated on the §2 decision + D.3 network inventory; v0.4 (a) delivers observed-flow topology, not full reachability computation.

## 7. Open decisions (operator)

1. **§2 reachability scope** — (a) flows + kg_writer only now, reachability computed in Stage 3 (rec); or (b) build reachability computation in this agent now.
2. Whether reachability edges are owned by network-threat or a Stage-3 graph-query capability.

## 8. Template note

Same shape as #712. HOLD: no execution PRs until approved.

## 9. Calendar estimate

~1 week for (a) (Zeek-conn wiring + kg_writer); +1-2 weeks if (b) reachability computation. Within Stage 1 envelope.

## 10. Cross-references

- Catalogue (#711): "C.x Network" — Network path / flow-event nodes, edges (`CAN_REACH`/`EXPOSED_TO`/`COMMUNICATES_WITH`), L4/L6.
- Directive §3 Stage 1.4 + Option X. Bounded-drain infra (A-1 #657).
- ADRs: no new ADR. Related ADR-009 (SemanticStore).
