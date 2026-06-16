# v0.4 Stage 1.3 (A-3 Item 2b) — D.6 K8s Posture CIS v2.0 + K8s inventory — brainstorm

**Status:** brainstorm for operator review (per-PR review). Template locked at #712 + §9/§10.
**Directive:** `v0-4-directive-2026-06-16.md` §3 Stage 1.3 + Option X. **Catalogue:** #711 "D.6 Kubernetes Posture (KSPM)".
**Agent:** `packages/agents/k8s-posture`. **Discipline:** depth-first; per-agent ownership; seal EMPTY; **Layer 23 transcription / Trigger #23 / Trigger #44** (CIS numbers — NEVER fabricate).

## 1. Current state (recon vs main `fec57f8`)

| Capability                                | State                                                                                   | Evidence                                                                  |
| ----------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| CIS version                               | **v1.8** (15-control ref set)                                                           | `cis/benchmark.py:13` `BENCHMARK_VERSION="1.8"`, `CIS_K8S_V18`            |
| kube-bench + Polaris                      | present (offline + live readers)                                                        | `tools/kube_bench*.py`, `tools/polaris.py`, `normalizers/polaris_live.py` |
| Manifest rules                            | 12 (10 v0.1 + 2 v0.3)                                                                   | `tools/manifests.py`                                                      |
| K8s objects discovered                    | **7 workload kinds only** (Pod/Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob) | `tools/` cluster_workloads reader                                         |
| RBAC inventory                            | `rbac/{enumerate,over_privileged}.py` **exist but NOT wired to run()**                  | `rbac/`                                                                   |
| Namespace/Service/NetworkPolicy inventory | **absent**                                                                              | —                                                                         |
| kg_writer.py                              | **absent**                                                                              | —                                                                         |
| run() output                              | OCSF **2003**; `findings.json` + `report.md`                                            | `agent.py`                                                                |

**Net-new:** CIS v1.8 → **v2.0** (authoritative data) · K8s inventory discovery (namespaces / workloads / RBAC / services / network policies + IRSA) · `kg_writer.py`.

## 2. Goal + scope boundary

- **Goal:** CIS v2.0 benchmark + full K8s cluster-internal inventory into the SemanticStore.
- **Covers:** CIS v2.0 catalog; inventory of cluster-internal objects + RBAC + IRSA bridge; kg_writer.
- **Does NOT cover:** the cloud control-plane node (D.3 EKS / D.5 AKS/GKE own it — D.6 annotates); image vulns (D.1); pod runtime behavior (D.3 Runtime).

## 3. Approach — per component (options + rec)

- **3a CIS v1.8 → v2.0.** ⚠️ **Data-gated** — needs **authoritative CIS-K8s v2.0 control data** (clean-room extraction; cite source; Layer 23 transcription verification; Trigger #44 STOP on numbering uncertainty). Rec: fetch authoritative v2.0 catalog → version-safe `CIS_K8S_V20` dict alongside v1.8 (keep both; version-pinned). **NEVER hand-transcribe control numbers.** This sub-PR BLOCKS on authoritative data.
- **3b K8s inventory discovery.** Extend the cluster reader from 7 workload kinds to the catalogue's full set (namespaces, services, endpoints, ingress, networkpolicies, configmaps, RBAC: role/rolebinding/clusterrole/clusterrolebinding, serviceaccounts). **Wire the existing `rbac/enumerate.py`** into the inventory path (it's built, undriven). Edges per catalogue: `RUNS_ON`, `USES_SERVICE_ACCOUNT`, `IRSA_MAPPING` (the cluster→cloud identity bridge to D.2 IAM roles), `SELECTS`, `OWNED_BY`, `GRANTS`, `BINDS`, `MOUNTS`.
- **3c kg_writer.** New `kg_writer.py` (copy-pattern). Q3/WI-K8 safety preserved: single-cluster-context (no cross-cluster leak).

## 4. Sub-PR breakdown (self-merge cascade; 3a gated on data)

1. PR1 `kg_writer.py` + K8s inventory node schema + wiring (no-op when None).
2. PR2 cluster inventory expansion (namespaces/services/networkpolicies + wire rbac/enumerate) + edges.
3. PR3 IRSA mapping edges (K8s SA → IAM role; D.2 bridge).
4. PR4 **CIS v2.0 catalog** (authoritative data; clean-room; Layer 23) — _gated on operator/authoritative source_.
5. PR5 cycle verification + coverage doc.

## 5. Substrate, invariants, gates

- Seal EMPTY (per-agent kg*writer; CIS catalog is agent-local additive). **Single-cluster-context invariant** (assert_single_cluster_context) preserved. CIS numbering: Trigger #23/#44 — STOP + fetch authoritative; never fabricate. Live behind `NEXUS_LIVE*\*`. Self-merge; Layer 27 before signal.

## 6. Coverage + honest limitations

- Coverage `[estimate]`. K8s inventory is a large catalogue contributor (cluster-internal graph). **Honest:** CIS v2.0 marginal coverage (mostly hygiene, per directive); RBAC inventory drives toxic-combo correlation later (A.4); realized inventory lift on live-cluster run.

## 7. Open decisions (operator)

1. **CIS v2.0 authoritative source** — operator provides / approves fetch? (gates PR4).
2. RBAC inventory depth — full object inventory vs the existing over_privileged heuristic.
3. IRSA edge scope (EKS only vs AKS/GKE workload-identity analogs).

## 8. Template note

Same shape as #712. HOLD: no execution PRs until approved.

## 9. Calendar estimate

~1-2 weeks for inventory + kg_writer (PR1-3); PR4 (CIS v2.0) gated on authoritative data — calendar starts when data lands. Within Stage 1 envelope.

## 10. Cross-references

- Catalogue (#711): "D.6 Kubernetes Posture" — nodes (cluster-internal objects), edges (`IRSA_MAPPING` etc.), L2-L4.
- Directive §3 Stage 1.3 + A-3 Item 2b + Option X. Triggers #23/#44 (CIS numbering).
- ADRs: no new ADR. Related ADR-007 (reference-agent pattern), ADR-009 (SemanticStore).
