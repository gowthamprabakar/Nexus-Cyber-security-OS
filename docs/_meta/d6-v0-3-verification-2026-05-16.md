# D.6 v0.3 verification record — 2026-05-16

Final-verification gate for **D.6 Kubernetes Posture Agent v0.3 (in-cluster ServiceAccount mode)**. Second Phase-1c slice for D.6; extends v0.2 (shipped 2026-05-16, 6/6) by adding `config.load_incluster_config()` so the agent can run as a Pod with a mounted SA token, no external kubeconfig required. **The production deployment mode.**

All four v0.3 tasks are committed; every pinned hash is in the [v0.3 plan](../superpowers/plans/2026-05-16-d-6-v0-3-in-cluster-mode.md)'s execution-status table.

---

## Gate results

| Gate                                                   | Threshold                                      | Result                         |
| ------------------------------------------------------ | ---------------------------------------------- | ------------------------------ |
| `pytest --cov=k8s_posture packages/agents/k8s-posture` | ≥ 80%                                          | **97%** (`k8s_posture.*`)      |
| `ruff check`                                           | clean                                          | ✅                             |
| `ruff format --check`                                  | clean                                          | ✅                             |
| `mypy --strict` (configured `files`)                   | clean                                          | ✅ (184 source files)          |
| Repo-wide `uv run pytest -q`                           | green, no regressions                          | **2094 passed, 11 skipped**    |
| v0.1 eval suite (10/10) via `k8s-posture eval`         | 10/10                                          | ✅                             |
| v0.1 + v0.2 driver + CLI tests                         | 100% green (no behavioural regression)         | ✅                             |
| **3-way workload-source mutual exclusion**             | manifest_dir / kubeconfig / in_cluster         | ✅ (agent.run + CLI both gate) |
| **In-cluster config-load error contract**              | ConfigException → ClusterReaderError           | ✅                             |
| **OCSF wire shape unchanged**                          | `K8sFindingType.MANIFEST` regardless of source | ✅                             |

### Repo-wide sanity check

`uv run pytest -q` → **2094 passed, 11 skipped**. +27 tests vs the v0.2 final baseline (2067); no regressions in any other agent or substrate package.

---

## Per-task surface

| Task                                                | Commit    | Tests | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------------------------- | --------- | ----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Reader extension (`in_cluster: bool = False`)    | `9477c3f` |     8 | Signature: `kubeconfig` becomes Optional + new `in_cluster: bool = False`. `_read_sync` branches `if in_cluster → load_incluster_config / elif kubeconfig → load_kube_config`. Q2 mutual exclusion + no-source-error before either loader. ConfigException → `ClusterReaderError` re-raise (Q3). Smoke (load_incluster_config importable) + happy path + finding-shape equality + ConfigException + Q2 + no-source + v0.2 preserved + namespace in in-cluster. |
| 2. Agent driver `in_cluster` plumbing               | `7f1356a` |     9 | `agent.run` gains `in_cluster: bool = False`. `_ingest` routes via `read_cluster_workloads(in_cluster=True, ...)` when set. 3-way workload-source mutual exclusion enforced at `agent.run` (ValueError on >1 set). v0.1 + v0.2 driver tests stay 100% green.                                                                                                                                                                                                   |
| 3. CLI `--in-cluster` flag                          | `7f1356a` |    10 | Boolean flag with 3-way mutual exclusion via click.UsageError. `--cluster-namespace` now accepts either `--kubeconfig` or `--in-cluster`. v0.1 + v0.2 CLI tests stay 100% green.                                                                                                                                                                                                                                                                               |
| 4. README + runbook v0.3 + this verification record | `4fec350` |     — | README v0.3 banner + dual-source bullet → triple-source bullet + new quick-start 3c (in-cluster). Runbook section 1c.iii adds full Pod-deployment example (ServiceAccount + ClusterRole + ClusterRoleBinding + CronJob manifest). Section 3 dual-invocation example becomes triple-invocation. Verification record (this).                                                                                                                                     |

**Test count breakdown for v0.3:** 8 + 9 + 10 = **27 new test cases**. Final k8s-posture test count is **309** (245 v0.1 + 37 v0.2 + 27 v0.3). Coverage: **97%** package-wide.

---

## Coverage delta

```
k8s_posture/__init__.py                       2      0   100%
k8s_posture/agent.py                         71      0   100%  ← up from 68 stmts (+3 for in_cluster routing)
k8s_posture/cli.py                           54      1    98%  ← up from 52 stmts (+2 for the new flag)
k8s_posture/dedup.py                         53      0   100%
k8s_posture/eval_runner.py                   90      5    94%
k8s_posture/nlah_loader.py                    9      0   100%
k8s_posture/normalizers/...                 124      2    98%
k8s_posture/schemas.py                       34      0   100%
k8s_posture/summarizer.py                    95      1    99%
k8s_posture/tools/__init__.py                 0      0   100%
k8s_posture/tools/cluster_workloads.py       59      1    98%  ← up from 49 stmts (+10 for in_cluster branch)
k8s_posture/tools/kube_bench.py              95      4    96%
k8s_posture/tools/manifests.py              142      8    94%
k8s_posture/tools/polaris.py                109      8    93%
---------------------------------------------------------------
TOTAL                                       937     30    97%
```

Coverage held at **97%** despite +15 statements across cluster_workloads.py + agent.py + cli.py.

---

## ADR-007 conformance — v0.3 reinforces the version-extension pattern

v0.3 is the second Phase-1c slice for D.6 (after v0.2). It confirms the version-extension pattern:

| Pattern                                      | v0.3 verdict                           | Notes                                                                                                                                                                                                          |
| -------------------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OCSF wire shape stable                       | ✅ **bit-for-bit unchanged**           | `K8sFindingType.MANIFEST` discriminator regardless of v0.1/v0.2/v0.3 source. Downstream consumers see no diff.                                                                                                 |
| Reuse of v0.1 analyser (`_analyse_manifest`) | ✅ **continues to hold**               | 10-rule analyser ships once; serves three reader sources now.                                                                                                                                                  |
| Async wrappers (ADR-005)                     | ✅ unchanged                           | Same `asyncio.to_thread` pattern.                                                                                                                                                                              |
| 3-way mutual exclusion generalised           | ✅ **first 3-way XOR in the platform** | Q6 (v0.2) was a 2-way exclusion (manifest_dir / kubeconfig). v0.3's Q2 extends to 3-way (+ in_cluster). The `workload_sources = sum(...)` pattern in `agent.run` + CLI is reusable for future D.6 v0.x slices. |
| Explicit-opt-in discipline (Q1)              | ✅ continues to hold                   | v0.2 Q4 ("explicit kubeconfig — no auto-detect") generalises into v0.3 Q1 ("explicit `in_cluster` — no SA-token probing").                                                                                     |
| CLI subcommand pattern                       | ✅ unchanged                           | Same `eval` + `run` shape; `run` gains one new flag.                                                                                                                                                           |

**No ADR-007 amendments surfaced.** v0.3 confirms the version-extension template the v0.2 verification record predicted: subsequent agents (F.3 v0.2, D.5 v0.2) will follow the same shape.

---

## D.6 deployment-mode matrix — now complete

| Mode | Plan slice | Workload source                                          | Use case                                                       |
| ---- | ---------- | -------------------------------------------------------- | -------------------------------------------------------------- |
| v0.1 | D.6 v0.1   | `--manifest-dir` — flat directory of `*.yaml`            | CI / PR scans of rendered Helm charts; airgapped review        |
| v0.2 | D.6 v0.2   | `--kubeconfig` — explicit kubeconfig file path           | Ad-hoc operator scans from a developer laptop                  |
| v0.3 | D.6 v0.3   | `--in-cluster` — mounted ServiceAccount token (Pod-side) | **Production deployment** — CronJob with read-only ClusterRole |

All three deployment modes share the same 10-rule analyser, same OCSF wire shape, same dedup behaviour, same summarizer output.

---

## Phase-1c progress for D.6

Two slices done; eight queued:

| Slice                                 | Status     | Notes                                                                                   |
| ------------------------------------- | ---------- | --------------------------------------------------------------------------------------- |
| D.6 v0.2 live workload ingest         | ✅ done    | [v0.2 verification](d6-v0-2-verification-2026-05-16.md)                                 |
| D.6 v0.3 in-cluster ServiceAccount    | ✅ done    | This record.                                                                            |
| D.6 v0.4 RBAC overpermissive analyser | ⬜ pending | Role / ClusterRole / RoleBinding / ClusterRoleBinding + 6-pattern overpermissive table. |
| D.6 v0.5 admission webhook posture    | ⬜ pending | `MutatingWebhookConfiguration` + `ValidatingWebhookConfiguration` checks.               |
| D.6 v0.6 Helm release inventory       | ⬜ pending | `read_helm_releases` via the Helm SDK.                                                  |
| D.6 v0.7 OPA / Gatekeeper             | ⬜ pending | Constraint templates + violations from `gatekeeper.sh`.                                 |
| D.6 v0.8 Pod Security Standards       | ⬜ pending | PSA API enforcement check (restricted / baseline / privileged).                         |
| D.6 v0.9 NetworkPolicy graph          | ⬜ pending | Depends on F.5 SemanticStore graph queries.                                             |

---

## Carried-forward risks

From the [v0.2 verification record](d6-v0-2-verification-2026-05-16.md) — most still hold:

1. **Frontend zero LOC** — unchanged.
2. **Edge plane zero LOC** — unchanged.
3. **Three-tier remediation zero LOC** — unchanged.
4. **Eval cases capped at 10/agent** — unchanged.
5. **Static intel snapshot (D.4)** — unchanged.
6. **Schema re-export lock-in** — 3 consumers (F.3 + D.5 + D.6). Unchanged.
7. ~~**Offline-mode v0.1 risk**~~ → mitigated by v0.2 + v0.3.
8. **GCP IAM rule shallowness (D.5)** — unchanged.
9. **Bundled 10-rule manifest analyser shallowness** — unchanged. v0.4 will expand to RBAC; subsequent slices expand other surfaces.
10. **Cross-tool dedup is rule-id-exact** — unchanged.
11. ~~**Helm chart inventory deferred**~~ → STILL DEFERRED; v0.6 owns it.
12. ~~**No in-cluster fallback**~~ → **CLOSED by v0.3.**
13. **No `kind`-cluster integration tests in CI** — unchanged. Reader tests still mock the SDK at the import site. A `kind`-backed `NEXUS_LIVE_K8S=1` suite remains a Phase-1c-late candidate.
14. **kubernetes SDK version drift** — unchanged.

New from v0.3:

15. **3-way mutual exclusion adds CLI complexity.** Operators must understand which workload source they want. **Mitigation:** the runbook section 1c.iii is the deployment-mode decision tree; --help string on each flag explicitly names the other two it conflicts with.
16. **In-cluster mode error messages must be operator-friendly.** A Pod that's misconfigured (e.g. SA not mounted) will see `failed to load in-cluster config (not running in a cluster?)` — this catches the common case but doesn't help if the env vars are set but the token file is unreadable. **Mitigation:** in v0.4 or v0.5, add structured error codes; for now the runbook's troubleshooting section will need a v0.3 row.

Closed by v0.3:

- ~~**Q1 explicit opt-in vs auto-detect**~~ → DONE (explicit `in_cluster=True`).
- ~~**Q2 mutual exclusion with kubeconfig**~~ → DONE (3-way XOR at reader + agent + CLI).
- ~~**Q3 in-cluster runtime probing**~~ → DONE (no probe; rely on `load_incluster_config()` raising).
- ~~**Q4 CLI flag name**~~ → DONE (`--in-cluster`).
- ~~**Q5 RBAC requirements documented**~~ → DONE (runbook section 1c.iii includes full SA + ClusterRole + ClusterRoleBinding + CronJob manifest).

---

## Sign-off

D.6 v0.3 is **production-ready for in-cluster ServiceAccount-token mode**. The agent now supports **all three deployment modes** (offline manifests / explicit kubeconfig / in-cluster Pod), each with bit-for-bit identical OCSF wire shape. The 3-way mutual-exclusion gate is enforced at the reader, agent, and CLI layers; ConfigException re-raises as `ClusterReaderError`; the runbook ships a complete Helm-snippet for the production CronJob deployment.

**Recommended next plan to write:** Per the user direction, **A.1 Tier-3 Remediation** is up next — the single biggest competitive gap closure vs Wiz. v0.3 closing means the Kubernetes detection track is fully operator-deployable; remediation is the natural next layer.

— recorded 2026-05-16
