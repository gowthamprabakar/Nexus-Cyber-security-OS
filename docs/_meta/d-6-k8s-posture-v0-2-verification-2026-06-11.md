# k8s-posture (operator "D.6" K8s Posture) v0.2 — Verification Record & Cycle Closure

**Date:** 2026-06-11 · **Cycle 8 of 17** · **Maturity: Level 1 → Level 2 (live cluster
posture).** The **first Group D (posture-class)** agent — the Group D pattern documented
here is inherited by **Compliance (Cycle 9)**. Single comprehensive directive, self-merge
cascade (Tasks 1–21), operator review at close (Task 22).

> **Naming note (please confirm).** The operator's directive titles this cycle "D.6 K8s
> Posture". The package's own README carries an **Agent-ID note (2026-05-20)** stating the
> identifier "D.6" is **reserved for the operator's Compliance agent**, and that this
> package is referenced by its package name **`k8s-posture`** in the codebase. This record
> uses `k8s-posture` for the package and treats "D.6" as the operator's cycle label. **No
> code claims the D.6 id.** Flagged per the ground-truth-before-asserting discipline.

---

## §1. Cycle summary

Took the k8s-posture agent from package **`__version__` 0.1.0 → 0.2.0** (ADR-010): live
kube-bench + Polaris execution against running clusters, a kubelet API client feeding
runtime posture rules, basic RBAC analysis, CIS v1.8 catalog, cloud-agnostic kubeconfig
auth, and a single gated live lane — all **alongside** the offline readers (Q1), keeping
OCSF 2003 byte-identical (WI-K5).

- **22 tasks, 22 PRs** (#433–#453 + this record). 8 milestones.
- **Tests:** k8s-posture **309 → 431 passed** (+122) + 1 gated-live skip. Full repo **5949
  passed, 65 skipped, 0 failed**.
- **Substrate seal EMPTY all 22** — no charter/shared edit (the `schemas.py` additions are
  k8s-local + additive). **No charter hoist** (as planned). Tasks consume the hoisted
  `charter.live_lane`.

## §2. Task execution table

| #   | Task                                             | PR        |
| --- | ------------------------------------------------ | --------- |
| 1   | Bootstrap (version + ADR-010 + OCSF 2003 verify) | #433      |
| 2   | Live kube-bench scan execution                   | #434      |
| 3   | Live kube-bench → OCSF 2003 normalization        | #435      |
| 4   | CIS K8s Benchmark v1.8 catalog                   | #436      |
| 5   | Live Polaris policy check execution              | #437      |
| 6   | Live Polaris → OCSF 2003 normalization           | #438      |
| 7   | Polaris custom policy support                    | #439      |
| 8   | kubelet API client                               | #440      |
| 9   | Runtime state enumeration                        | #441      |
| 10  | Runtime posture rules                            | #442      |
| 11  | RBAC resource enumeration                        | #443      |
| 12  | Over-privileged RBAC detection                   | #444      |
| 13  | RBAC + runtime finding emission (OCSF 2003)      | #445      |
| 14  | Per-cluster scan-context isolation               | #446      |
| 15  | Kubeconfig credential safety wrapper             | #447      |
| 16  | EKS + AKS + GKE auth resolution via kubeconfig   | #448      |
| 17  | NEXUS_LIVE_K8S_POSTURE gated lane                | #449      |
| 18  | WI-K4 HARD live cluster e2e                      | #450      |
| 19  | Live-lane coexistence (16 lanes)                 | #451      |
| 20  | Cross-agent OCSF 2003 sweep (3 emitters)         | #452      |
| 21  | Per-tool coverage + runbooks + README v0.2       | #453      |
| 22  | Verification record + cycle closure              | _this PR_ |

## §3. Q-lock mapping (all 7 honored)

| Q   | Lock                                                     | Where honored                                                                                                                 |
| --- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Q1  | (A) kube-bench + Polaris + kubelet live; webhooks → v0.3 | live scanners + kubelet client (Tasks 2–10) alongside offline readers                                                         |
| Q2  | (A) EKS + AKS + GKE + self-managed via kubeconfig        | `cluster_auth.resolve_cluster` / `detect_provider` (Task 16)                                                                  |
| Q3  | (A) single-cluster per scan; multi-cluster → v0.3        | `isolation.assert_single_cluster_context` + `ClusterScanSession` (Task 14)                                                    |
| Q4  | (B) basic RBAC enumeration + over-priv; full sim → v0.3  | `rbac/` heuristic (Tasks 11–12); **no** effective-perms sim                                                                   |
| Q5  | (C) reference D.3 Falco; D.6 emits posture-shape only    | **no Falco code in k8s-posture** — runtime rules use kubelet enumeration; D.3 owns Falco (clean 2003-vs-2004 domain boundary) |
| Q6  | (A) admission webhooks out of scope; → v0.3              | not implemented (explicit v0.3)                                                                                               |
| Q7  | OCSF class_uid 2003 (byte-identical)                     | verified + pinned (WI-K5); 3rd emitter (F.3/D.5/D.6)                                                                          |

## §4. Gates passed

- **All 5 CI checks green** on every one of the 21 self-merged PRs.
- **Substrate seal EMPTY** for all 22 tasks (no charter/shared edit; `schemas.py` additions
  are k8s-local + additive new finding types).
- **OCSF 2003 byte-identical** every task: live readers added _alongside_ offline; live
  findings normalize via the **shared** normalizers (`to_dict()` equality tests); the new
  `RUNTIME`/`RBAC` finding types are emitted **only on the live path**, so the offline
  `run()` + 10 eval cases are unchanged (WI-K5).
- **WI-K4 live lane** green: two-layer e2e (offline every push + gated
  `NEXUS_LIVE_K8S_POSTURE=1`), Task 18; **lane coexistence** 16 distinct lanes (Task 19).
- **Cross-agent sweep** (Task 20, WI-K6): **3** OCSF 2003 emitters + 5 consumers,
  2200 passed / 31 skipped / **0 failed**.
- **Q3/WI-K8 isolation invariant** held: `assert_single_cluster_context` +
  `ClusterScanSession.assert_belongs` reject cross-cluster context leak (pause-trigger #12).
- **WI-K9** kubeconfig secrets never logged (`SafeKubeconfig` repr + `redact_kubeconfig`).
- **ruff + ruff format + mypy strict** clean per task; tool-proxy boundary inherited.

## §5. Honest findings (WI-K3)

- **The defining gap — live scan → OCSF production loop is NOT wired (v0.3).** Like
  D.3/D.4/D.8's §5, v0.2 ships the live-scan _infrastructure_ + detection/emission _building
  blocks_, all unit- and e2e-tested **through emission**. But the live scanners are **not**
  driven from the agent's `run()` path — the **offline `run()` remains the only OCSF-2003-
  emitting path** (deliberately, WI-K5). So "scan a live cluster → emit OCSF findings" is
  not an end-to-end production capability at v0.2; it is the largest v0.3 carry-forward.
- **Wiz-weight target was ~75%; realistic realized ~30–35% `[estimate]`.** The live
  execution + kubelet/RBAC breadth move the agent toward L2, but because the production loop
  above is deferred, the _realized_ capability is nearer the v0.1 baseline. Stated plainly
  per WI-K3.
- **RBAC is a basic heuristic, not a full effective-permissions sim** (Q4 → v0.3).
- **Admission webhooks + multi-cluster batch + runtime drift are out of scope** (Q3/Q6 → v0.3).
- **Coverage is breadth, not depth, per-tool (WI-K1, no aggregate):** kube-bench ~55–65%,
  Polaris ~50–60%, runtime ~40–50%, RBAC ~35–45% — all `[estimate]`.
- **Two pre-existing README discrepancies surfaced, not overwritten (ground-truth discipline):**
  (1) the **agent-ID note** — "D.6" is reserved for Compliance; package = `k8s-posture`;
  (2) a pre-existing **dated maturity narration** ("v0.2/v0.3 @ 2026-05-16") independent of
  the actual `__version__` field (which was 0.1.0 before this cycle's ADR-010 bump). The new
  README banner is labeled as the package-version bump to avoid contradiction.

## §6. Watch-items carry-forward

- **WI-K2:** the **Group D posture-class pattern** (live tool execution via injectable
  runner + shared-parser byte-identical normalization + single-cluster isolation +
  kubeconfig safety + cloud-agnostic auth + single gated lane) is documented here for
  **Compliance (Cycle 9)** to inherit.
- The honest-findings gaps above, foremost the **live-scan → OCSF run-loop wiring**.
- The two README naming/version discrepancies (§5) for operator disposition.

## §7. v0.3 deferred handoff

Admission webhooks (Q6) · multi-cluster batch scanning (Q3) · **full effective-permissions
RBAC simulation** (Q4) · runtime drift detection · in-cluster Job execution of kube-bench /
live `polaris audit` end-to-end · kubelet per-node rate-limit backoff (WI-K10) · and the
headline item: **wiring the live scanners into the agent's `run()` → OCSF 2003 loop**.

## §8. Cross-references

- Cross-agent sweep: `d-6-k8s-posture-v0-2-cross-agent-sweep-2026-06-11.md`
- Per-tool coverage: `d-6-k8s-posture-v0-2-{kube-bench,polaris,kubelet}-coverage-2026-06-11.md`
- Runbooks: `packages/agents/k8s-posture/runbooks/{kube_bench_live,polaris_live,kubelet_runtime}.md`
- OCSF 2003 emitter siblings: F.3 Cloud Posture, D.5 Multi-Cloud Posture (3 emitters now).
- Group D posture-class pattern: **consumer #1** (k8s-posture); Compliance = #2 (Cycle 9).

---

**k8s-posture (operator "D.6" K8s Posture) v0.2 — CYCLE CLOSED ✅** (pending operator merge
of this record). 22/22 tasks, 8/8 milestones, substrate seal empty throughout, 0 failures,
Q3/WI-K8 single-cluster isolation invariant held, OCSF 2003 byte-identical.
