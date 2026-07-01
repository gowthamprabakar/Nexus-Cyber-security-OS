# Graph-Moat Roadmap — the complete detector → graph → attack-path arc

**Created 2026-07-01.** The anti-drift anchor. We pull the next item from the ordered backlog; we do
not improvise, and anything new gets added here before we start it.

## North Star (unchanged)

Customer connects a cloud account → within minutes sees their **top ~10 real attack paths,
prioritized, each with a fix**, at a measured ~50–60% of Wiz value.

## Locked principles (do not re-litigate)

1. **The graph is the moat.** Detectors exist to power attack paths — node + edge + property
   contributions. Causality is detector → graph → path, never the reverse.
2. **One edge at a time.** Edge = provider-agnostic contract; detector = per-cloud implementation.
   AWS-first to prove the contract, then complete across the clouds _that path needs_.
3. **Done = watched it work**, and **not dormant** — a slice ends only when its detector runs in a
   real (fixture-driven) `run()` and writes its edges, plus a red-team bank + an e2e proving the
   _path emerges_. Test-only edges are dormancy debt, which is the thing we are avoiding.
4. **Honest gaps surfaced, not faked.** Live readers operator-gated (`NEXUS_LIVE_*`); fixtures prove.

---

## THE COMPLETE ARC (the whole mountain)

A path = **SOURCE (foothold) → [traversable edges] → SINK (impact)**. The moat is full coverage of
sources × edges × sinks across the cloud kill-chain × 4 clouds (AWS / Azure / GCP / K8s) — plus the
wiring that makes a real run build it. Status from the live catalog (72 edge types defined, ~24
produced, 16 traversable, 19 named archetypes, 10 sources, 4 sinks):

| Kill-chain stage            | Mechanism                                                                                                                                                                | Status                  |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| **1. Foothold (SOURCES)**   | public resource, resource-policy grant, external identity, any principal, privileged K8s pod, exposed AI svc, runtime detection ×2, over-scoped OAuth, leaked credential | ✅ 10 sources           |
|                             | exposed-DB-as-source, compromised CI/CD/build, public registry, serverless/function-URL                                                                                  | ❌ missing              |
| **2. Credential access**    | leaked-cred → owner (`OWNED_BY`)                                                                                                                                         | ✅ AWS+GCP              |
|                             | `STORES_SECRET`, env/secrets-manager exposure, secret→KMS                                                                                                                | ❌ no path              |
| **3. Privilege escalation** | `CAN_ESCALATE_TO` (AWS+Az+GCP), `ASSUMES` (AWS)                                                                                                                          | ✅                      |
|                             | K8s RBAC escalation, SA-token escalation, Az/GCP `ASSUMES`                                                                                                               | ❌ missing              |
| **4. Lateral movement**     | `CAN_REACH` (config, AWS), `COMMUNICATES_WITH` (observed)                                                                                                                | ✅ partial              |
|                             | `POD_CAN_REACH` (K8s), `PEERED_WITH`/`ROUTES_TO`/`IN_VPC` (topology), CAN_REACH Az/GCP                                                                                   | 🟡/❌                   |
| **5. Access leg**           | `HAS_ACCESS_TO`, `IRSA_MAPPING` (produced, **not traversable**)                                                                                                          | ✅ / 🟡                 |
|                             | `MOUNTS` (pod→secret), `USES_SERVICE_ACCOUNT`                                                                                                                            | ❌ missing              |
| **6. Impact (SINKS)**       | sensitive_data, known_vuln, ai_model, saas_tenant                                                                                                                        | ✅ 4 sinks              |
|                             | KMS-key compromise, DB exfil-terminal, model/training poison, crypto-mine/ransom                                                                                         | ❌ missing              |
| **7. Cross-domain**         | `DEFINED_IN`, `DEPLOYED_VIA`, `RUNS_IMAGE`, `HOSTS_AI`, `SERVES_MODEL`                                                                                                   | ✅                      |
|                             | `BUILT_FROM` (image→repo), SBOM supply-chain, `TRAINED_ON`                                                                                                               | 🟡/❌                   |
| **Cross-cutting**           | per-cloud completion (every edge × 4 clouds); **wiring** (run detectors in `run()`)                                                                                      | partial / ❌ none wired |

**Honest scope: ~7 stages × ~25–40 edge-implementations × up to 4 clouds + wiring = months, not
days.** We've built ~4 edges (stages 2/3/4) ≈ 10–15% of the moat. This table is the scope reference;
the backlog below is the _sequenced subset_ we actually execute.

## Decisions (my call, taken 2026-07-01)

- **Sequencing = highest-value real-breach paths first** (Capital-One SSRF, leaked-key sprawl,
  public-bucket, K8s escape, cross-account), NOT tidy completion of low-value defined edges.
  AWS-first per edge, then across clouds only where that path needs it.
- **Wiring = wire-as-we-go**, and the FIRST work is wiring the _existing_ edges — they are built but
  dormant (test-only), which is precisely the risk we flagged.

---

## ORDERED BACKLOG (pull the top item)

### W0 — Verify the merge landed (30 min)

`grep` main for `CAN_REACH`, `secret_fingerprint`, `record_reachability`, azure/gcp
`escalation_grants`, `sa_key_ownership`. MERGED ≠ in main (stacked-squash hazard). Re-land any gaps.

### W1 — Make the existing moat REAL (un-dormant) ★ first

Wire identity's moat detectors (`CAN_ESCALATE_TO`, `OWNED_BY` owner-side, `HAS_ACCESS_TO`) into
`identity.run()` so a fixture-fed run writes them — not just a test calling the writer. Then a single
end-to-end runner: planted fixture → real agent `run()`s → shared graph → `build_report_card` →
rendered card. **DoD:** one entry point produces the card from agent runs, no hand-seeding.

### W2 — K8s container-escape → cluster takeover (new path family)

`privileged_workload` is a source with no impact edge. Add the edge a privileged/escaped pod uses to
reach cluster secrets / node / cluster-admin (`MOUNTS` / RBAC). Wire into k8s agent run. _EKS first._

### W3 — Cross-account trust abuse

External principal `ASSUMES` a role in another account that reaches data — full cross-account path.

### W4 — Network-topology lateral movement

`CAN_REACH` across Azure NSG / GCP firewall, and `POD_CAN_REACH` / VPC `PEERED_WITH` reachability —
complete the lateral-movement stage beyond AWS config.

### W5 — Supply-chain / code-to-cloud

`BUILT_FROM` (running image → its repo) + SBOM `CONTAINS_PACKAGE` → vuln — a code-to-cloud breach path.

### W6 — Credential-access depth

`STORES_SECRET` (a resource/workload holds a secret) → its blast radius; secrets-manager exposure.

### Backlog / lower

Azure SP-secret leaked-cred (W-A3, hard extraction); new SINKS (KMS, DB-exfil, model-poison); report-
card polish (named-path ULID→ARN labels; leg subsumption); per-cloud completion of shipped edges.

## Explicitly NOT now (drift guard)

❌ Remediation one-click / wiring the remediation agent (the `_FIX` hint is enough — moat is the graph).
❌ Live cloud wiring (operator-gated; fixtures prove). ❌ Breadth with no new edge/path-shape.
❌ DSPy / meta-harness cadence / other v0.5 items.
