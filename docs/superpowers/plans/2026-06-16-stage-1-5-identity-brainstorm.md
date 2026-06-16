# v0.4 Stage 1.5 — D.2 Identity per-role evaluation depth + identity inventory — brainstorm

**Status:** brainstorm for operator review (per-PR review). Template locked at #712 + §9/§10.
**Directive:** `v0-4-directive-2026-06-16.md` §3 Stage 1.5 + Option X. **Catalogue:** #711 "D.2 Identity (CIEM)".
**Agent:** `packages/agents/identity`. **Discipline:** depth-first; per-agent ownership; seal EMPTY; live gated; offline byte-identical.

## 1. Current state (recon vs main `fec57f8`)

| Capability                | State                                                                                                                                        | Evidence                                      |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| Inline policy             | **names only** (documents NOT fetched)                                                                                                       | `tools/aws_iam.py:299-306`                    |
| Managed policy docs       | fetched (customer-managed, default version)                                                                                                  | `tools/aws_iam.py:159-196`                    |
| Effective-perms simulator | **built + gated** (`assess_effective_perms=False` default); CURATED_RISK_ACTIONS (4); `resources=("*",)`; conditions ignored; single-account | `agent.py:139,283-319`; `permission_paths.py` |
| Finding types             | OVERPRIVILEGE / DORMANT / EXTERNAL_ACCESS / MFA_GAP / FEDERATION                                                                             | `normalizer.py`                               |
| kg_writer.py              | **absent**                                                                                                                                   | —                                             |
| Identity edges            | implicit only (memberships/attachments as string tuples; no first-class edges)                                                               | `aws_iam.py:85-92`                            |

**Net-new (per-role evaluation depth — the 7 recon gaps):** inline-policy **document fetch** · IAM **condition** evaluation · **per-resource ARN** patterns (not just `*`) · **trust-chain / transitive** assume-role paths · permission-boundary explicit analysis · transitive group closure · drive the gated simulator into the default path. Plus identity inventory + `kg_writer.py`.

## 2. Goal + scope boundary

- **Goal:** deepen effective-access evaluation beyond the gated admin-pattern path AND write the identity graph (nodes + access edges) to the SemanticStore.
- **Covers:** inline-policy doc fetch + semantic evaluation; conditions; per-resource ARNs; trust chains; identity nodes/edges (the catalogue's D.2 owns these); kg_writer.
- **Does NOT cover:** the cloud resources identities reach (D.3/D.5 own those nodes — D.2 writes `HAS_ACCESS_TO` edges onto them per catalogue); OS-level auth events (D.3 Runtime contributes); SaaS identity unless federated (D.10).

## 3. Approach — per component (options + rec)

- **3a Inline-policy document fetch.** Fetch inline policy documents (today only names). Feeds semantic evaluation. Self-merge.
- **3b Per-role evaluation depth.** Drive the existing simulator (`_simulate_effective_grants`) into a non-default-OFF depth path: per-resource ARN patterns (beyond `*`), IAM condition evaluation, permission-boundary explicit analysis. Rec: keep the gated flag for the _live AWS SimulatePrincipalPolicy_ calls (cost), but deepen the evaluation logic + evidence (admin_actions/admin_resource_patterns already in normalizer).
- **3c Trust-chain / transitive.** Trace assume-role chains (A→B→C) + transitive group closure → `CAN_ESCALATE_TO` edges (catalogue D.2).
- **3d Identity inventory + kg_writer.** New `kg_writer.py` (copy-pattern) writing the catalogue's D.2 nodes (IAM user/role/policy/boundary/SCP/group/federation/SA) + edges (`ASSUMES`/`HAS_ACCESS_TO`/`MEMBER_OF`/`ATTACHED_TO`/`TRUSTS`/`CAN_ESCALATE_TO`/`BOUNDED_BY`). `HAS_ACCESS_TO` edges land on D.3/D.5 resource nodes.

## 4. Sub-PR breakdown (self-merge cascade)

1. PR1 inline-policy document fetch + semantic parse.
2. PR2 `kg_writer.py` + identity node/edge schema + wiring (no-op when None).
3. PR3 per-resource ARN + condition evaluation depth (simulator path).
4. PR4 trust-chain + transitive group closure → `CAN_ESCALATE_TO`.
5. PR5 cycle verification + coverage doc.

## 5. Substrate, invariants, gates

- Seal EMPTY (per-agent kg_writer; evaluation additive). Cross-tenant guard in kg_writer. Live AWS sim behind the existing gate (cost). Offline byte-identical (default path unchanged unless flag). Self-merge; Layer 27 before signal.

## 6. Coverage + honest limitations

- Coverage `[estimate]`. Per-role depth + identity graph (high-value for A.4 toxic-combo/attack-path). **Honest:** multi-account SCP boundaries still single-account-phase; conditions evaluation is bounded (not a full policy-eval engine); live simulator calls cost money (gated); realized depth lands on operator-run of the gated lane.

## 7. Open decisions (operator)

1. Drive the simulator into the **default** path (always-on deeper eval, offline-deterministic) vs keep gated — cost tradeoff.
2. Trust-chain depth cap (3-hop to match SemanticStore `MAX_TRAVERSAL_DEPTH=3`?).
3. Multi-account SCP in scope for v0.4 or v0.5?

## 8. Template note

Same shape as #712. HOLD: no execution PRs until approved.

## 9. Calendar estimate

~1-1.5 weeks (per-role eval depth + kg_writer; simulator already built). Within Stage 1 envelope.

## 10. Cross-references

- Catalogue (#711): "D.2 Identity (CIEM)" — identity nodes, access-edge layer (L4: `HAS_ACCESS_TO`/`ASSUMES`/`CAN_ESCALATE_TO`).
- Directive §3 Stage 1.5 + Option X. A-4 effective-perms work (#688/#692).
- ADRs: no new ADR. Related ADR-009 (SemanticStore), ADR-016 (tool-proxy for sim calls).
