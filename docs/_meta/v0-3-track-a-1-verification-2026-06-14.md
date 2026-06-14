# v0.3 / Phase D — Track A Workstream A-1 verification record (live-loop wiring) — 2026-06-14

> **Status:** A-1 CLOSED. The live→OCSF run-loop foundation is wired across 5 agents.
> Self-merge cascade; substrate seal EMPTY throughout. This record closes the workstream
> opened by [the A-1 launch doc](v0-3-track-a-1-launch-2026-06-14.md) (§9 addendum included).

## 1. What A-1 delivered

Each of the 5 in-scope agents can now drive its OCSF emitter from a **live** source through
its production `run()` path, behind the agent's existing `NEXUS_LIVE_*` gate — with the
offline/stub path preserved **byte-identical** as the default. The fleet's detect loop is
live-capable where it was offline-only.

## 2. The 5 wired agents

| #     | agent          | PR   | live source wired                                     | mechanism                                                          |
| ----- | -------------- | ---- | ----------------------------------------------------- | ------------------------------------------------------------------ |
| A-1.1 | threat-intel   | #653 | live NVD / CISA-KEV / MITRE (`live_feeds`)            | `_ingest` live route; readers return offline record shapes         |
| A-1.2 | vulnerability  | #654 | live ECR / ACR / GCR registry (`registry_type`)       | `_scan_registry`; both routes converge on `trivy_to_findings`→2002 |
| A-1.3 | identity       | #655 | SAML/OIDC federation, AWS+Azure (`detect_federation`) | `federation_to_findings` additive 2nd emitter                      |
| A-1.4 | network-threat | #659 | Suricata + Zeek-DNS push streams                      | `bounded_drain` over injected stream + existing normalizers        |
| A-1.5 | runtime-threat | #660 | Falco + Tracee push streams                           | `bounded_drain` over injected stream + existing normalizers        |

**Shared infrastructure:** [`#657`] `nexus_runtime.realtime.bounded_drain` — the
agent-agnostic count/time-bounded drain that lets a single-shot `run()` consume an infinite
push stream (operator-reviewed, abstraction-only). A-1.4 + A-1.5 consume it.

## 3. Per-PR invariants held (every A-1 PR)

- **Default-OFF gated:** the live path is reached only via an explicit param/flag; the agent's
  `NEXUS_LIVE_*` lane gates real sockets/cloud. Never default-on in CI.
- **Byte-identical offline:** with the live switch unset, OCSF emission is unchanged
  (regression-guarded by each package's offline suite).
- **Mutual exclusion:** live source ⊥ the corresponding offline input, where applicable.
- **Substrate seal EMPTY:** no `packages/shared` / `packages/charter` change in any A-1 PR.
- **Green:** each agent's full package suite + ruff + mypy clean; new tests per PR.

## 4. The 4 reclassifications (Split decision, §9 addendum)

A 6-agent recon found "pure wiring" held for only 3 of the original agents; the operator's
**Split** decision moved the net-new work to depth:

| reclassified                                    | to                     | reason                                             |
| ----------------------------------------------- | ---------------------- | -------------------------------------------------- |
| multi-cloud-posture Azure/GCP findings scanners | **A-3**                | no live scanners exist (net-new build)             |
| k8s-posture live kube-bench/Polaris runners     | **A-3**                | no production runner exists (only test fakes)      |
| synthesis fleet source 3→12 (+ Q6 scrub)        | **dedicated depth PR** | adapter + Q6 safety replication for 9 agents       |
| data-security Azure/GCS multi-cloud emission    | **A-6**                | two-pipeline (unify→frameworks ≠ S3 detectors)     |
| identity Azure-AD _identity_ detection          | **A-4**                | shape-disjoint `AzureAdListing`, no emit path      |
| Zeek-conn → FlowRecord adapter                  | **follow-up**          | adapter does not exist (Zeek-DNS shipped in A-1.4) |

## 5. Honest scope (what A-1 is and is NOT)

- **IS:** the wiring foundation — every in-scope agent's `run()` can now emit OCSF from a live
  source. CI proves the wiring with injected fake streams / mocked live readers (deterministic).
- **IS NOT:** a live-coverage measurement. The Wiz-weighted lift the directive estimated
  (~+5–8pp) is **realized when the live lanes actually run** against real sources — an
  operator-run activity (gated, costs money). A-1 makes that possible; it does not by itself
  move the offline-measured number. This mirrors the v0.2 "live green is operator's to run;
  CI proves the wiring" honesty.
- **Deferred (named above):** Zeek-conn→FlowRecord; production kube-bench/Polaris + cloud
  scanners; real gRPC/pipe sensor clients for Falco/Tracee; Azure-AD identity detection;
  synthesis fleet+Q6. These are tracked to A-3/A-4/A-6/follow-up, not dropped.

## 6. Next

Per the v0.3 sequence, with A-1 closed the following run in parallel:

- **Track C C-1** — A.4 DSPy `compilation_cadence` wiring (volume-based trigger +
  SemanticStore storage, per Q-C1-1/Q-C1-2). Prereqs (#648 hoist, #650 pins, Task-5) satisfied.
- **Track D D-2** — per-tenant cadence config + freshness-signal API + continuous-mode metrics
  (D-1 CLI wiring landed in #658).

## 7. References

- A-1 launch + §9 addendum — `v0-3-track-a-1-launch-2026-06-14.md`.
- PRs: #653, #654, #655, #657 (infra), #659, #660; addendum #656; Track D D-1 #658.
- v0.3 / Phase D directive (operator, 2026-06-14) — Track A §A-1.
