# Deep Seam Analysis — layers 1–4 and the interactions between them (2026-07-02)

The value is in the **seams** (the interfaces), not the layers. Four layers, three seams:

```
Layer 1 DETECTION ──[Seam A: write]──▶ Layer 2 GRAPH ──[Seam B: read]──▶ Layer 3 ATTACK-PATH ──[Seam C: merge]──▶ Layer 4 OUTPUT
```

---

## LAYER 1 — DETECTION (internal state)

**20 agents. 14 write to the graph, 6 do not.**

- **Non-writers (6):** `compliance`, `curiosity`, `meta-harness`, `synthesis`, `threat-intel`, `supervisor`
  — LLM / orchestration / compliance roles that don't own spine nodes (by design).
- **Writers that feed attack paths (12):** identity, cloud-posture, data-security, k8s-posture, network-threat,
  vulnerability, aispm, appsec, sspm, runtime-threat (each writes ≥1 **traversable** edge).
- **⚠️ Writers whose output is graph-DEAD for attack paths (2):** `multi-cloud-posture` and `compliance`
  write **only `AFFECTS`** (finding→resource), which is **not traversable**. Their detection work lands as
  decoration, **never on an attack path.** This is a concrete instance of the dormancy risk.

**Interaction-relevant fact:** a detector only "powers a path" if it writes a **traversable edge** or a
**source/sink-marked node**. Writing a `MISCONFIGURATION_FINDING` + `AFFECTS` does neither.

---

## SEAM A — Detection → Graph (the WRITE seam) — 🟡 works, but convention-not-contract

**Mechanism:** each agent's `kg_writer` upserts nodes keyed by a canonical id and adds edges. Convergence
(agent X's node == agent Y's edge endpoint) is how independent signals collapse onto ONE node.

**The convergence contract is thin — only 3 explicit key builders** (`charter.canonical`):
`secret_fingerprint` (leaked creds), `azure_blob_uri` (Azure storage), `gcs_uri` (GCS). **AWS resources
join by raw ARN with no builder** — convention, not contract. So for ~16 node categories, only storage +
secrets have an enforced join key; **compute / KMS / RDS / roles rely on every agent formatting the ARN
identically.**

**Status: 🟡 healthy for the built paths, structurally fragile.**
- ✅ Proven: identity's `HAS_ACCESS_TO`→resource ARN converges with cloud-posture/data-security's
  `CLOUD_RESOURCE` ARN (every moat e2e depends on this and passes).
- ⚠️ Risk: **silent join failure.** The exact bug we already hit — data-security keyed a bucket by
  `bucket.name` while others used the ARN → two disconnected nodes, no path. Fixed for S3; the *class* of
  bug is unguarded for compute/KMS/RDS. There is **no test that asserts cross-agent key convergence**
  except per-path e2es.

---

## LAYER 2 — GRAPH (internal state)

- **~72 edge types defined · 28 produced · 21 traversable · ~16 node categories produced · 14 source markers · 4 sink markers.**
- **Produced but NOT traversable (7):** `AFFECTS`, `ATTACHED_TO`, `MEMBER_OF`, `OWNS`, `CONTRIBUTES_TO`,
  `HOSTS_AI`, `BINDS`.
  - Correctly excluded (control-plane / structure / reverse-direction): `AFFECTS`, `ATTACHED_TO`,
    `MEMBER_OF`, `OWNS` (the attack direction is its reverse `OWNED_BY`).
  - **⚠️ Real gaps:** `BINDS` (K8s ServiceAccount → RBAC role) is written but not traversable → a pod's SA
    bound to **cluster-admin** is invisible to the walker. `HOSTS_AI` similar.
- **Traversable but NOT produced: 0** — healthy, no dead-end traversable edges.
- **⚠️ Graph-dead nodes:** `POLICY` (only `ATTACHED_TO`, non-traversable) and `MISCONFIGURATION_FINDING`
  (only `AFFECTS`) are written but can never appear on a path.

---

## SEAM B — Graph → Attack-Path (the READ seam) — 🟢 mostly healthy

**Mechanism:** two readers over the same graph:
1. **Generic engine** (`find_candidate_paths` → `walk_paths`, a recursive-CTE BFS) from every **source-marked**
   node, following only **traversable** edges, stopping at the first **sink-category** node; novelty-filtered.
2. **Named detectors** (`kg_query` `find_*`, 19 archetypes) — hardcoded source→sink shapes.

**Status: 🟢 the pipe is connected — every traversable edge has a producer, sinks are distinct categories.**
- ✅ Sinks are on distinct node categories (`DATA_CLASSIFICATION`, `CVE_FINDING`, `AI_MODEL`, `SAAS_TENANT`)
  — the walker never stops at an intermediate.
- **⚠️ Coverage gaps at this seam:**
  - Only **4 sink categories** → "reaching a KMS key / database / a stolen secret" is **not** modelled as
    impact (a walker limitation: KMS/DB are `CLOUD_RESOURCE`, and making that a sink would halt every path
    at the first resource).
  - `BINDS` non-traversable → **K8s RBAC privilege-escalation** paths don't exist yet.
  - Source markers exist for 8 categories; produced-but-unmarked categories (`POLICY`, finding nodes) are
    inert.

---

## LAYER 3 — ATTACK-PATH (internal state)

- **Named archetypes: 19** (`crown_jewel`, `fine_grained_data`, `lateral_movement`, `privilege_escalation`,
  `leaked_credential`, `external_trust`, `runtime_exploit`, `exposed_kms_key`, …).
- **Generic engine:** depth-4 BFS, novelty-filtered against the **19 `NAMED_SHAPES`** so it only surfaces
  *new* multi-hop combinations.
- **This arc's ~10 edge families produce paths ONLY via the generic engine** — the named ranker uses the
  *pre-existing* edges (`ASSUMES`, `OWNS`+`DEFINED_IN`, `COMMUNICATES_WITH`).

---

## SEAM C — Attack-Path → Output (the MERGE seam) — 🟢 clean

**Mechanism:** `build_report_card` merges the two path systems:
- `AttackPathRanker.find_all()` (named, authoritative) + `find_candidate_paths()` (generic, novel).
- The generic engine already **novelty-filters** vs the 19 named shapes; `report_card` adds cross-source-id
  dedup (`named_entities_by_type`), C1 label resolution, C2 leg subsumption.

**Status: 🟢 healthy and the only merge point.**
- ✅ No double-counting (novelty fence + entity-overlap dedup).
- **⚠️ Structural note:** there are **two parallel path-production systems** that meet **only inside
  `report_card`.** Anyone calling `find_all()` directly (e.g. an API that predates the report card) gets the
  named paths but **none of the moat paths.** The report card is the single point of truth for "all paths."

---

## END-TO-END INTERACTION MAP (with per-hop status)

```
DETECTION            SEAM A (write)         GRAPH              SEAM B (read)        ATTACK-PATH        SEAM C (merge)     OUTPUT
12 path-feeding  ──▶ 🟡 ARN-convention  ──▶ 28 edges /     ──▶ 🟢 21 traversable ──▶ 19 named +     ──▶ 🟢 clean merge ──▶ report
  agents             join (3 contracts)     16 node types      + 4 sinks             generic engine     + dedup/labels     card
 2 dead agents   ──▶ ✗ AFFECTS-only      ──▶ (7 dead edges,   ──▶ ⚠️ BINDS/KMS/DB   ──▶ ~10 moat        ──▶ ⚠️ only merge  ──▶ (fix
 (compliance,        (never on a path)      2 dead nodes)         gaps                  families            point here)        hints)
  multi-cloud)
```

## The 3 biggest INTERACTION problems (ranked)

1. **Two detection agents write only dead edges** (`compliance`, `multi-cloud-posture` → `AFFECTS`).
   Their detection never reaches an attack path. Either give them traversable edges or accept they're
   findings-only (and say so).
2. **Convergence is convention, not contract** for most node types. Only 3 canonical key builders guard ~16
   node categories; a single ARN-format mismatch silently disconnects the graph (the bug class we already
   hit once). **No cross-agent key-convergence test exists.**
3. **Sub-shapes are invisible at Seam B:** `BINDS` non-traversable (K8s RBAC privesc) and only 4 sink
   categories (no KMS/DB/credential-theft-as-impact). Whole real attack families can't form yet.

## What each seam needs next

- **Seam A:** a canonical key builder per resource type + a cross-agent convergence test (kills the silent-
  join risk). Wire `compliance`/`multi-cloud-posture` findings to traversable edges or mark them findings-only.
- **Seam B:** make `BINDS` traversable (K8s RBAC), and design distinct sink node-categories for KMS/DB so the
  walker can terminate there without halting mid-path.
- **Seam C:** healthy — but fold the two path systems so `find_all` and the generic engine share one entry
  point (the report card), so no consumer can miss the moat paths.
```
