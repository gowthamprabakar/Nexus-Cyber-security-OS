"""Nexus Kubernetes Posture Agent — D.6 / Agent #9 under ADR-007.

The fourth Phase-1b agent — **closes the Phase-1b detection track**.
Adds CIS Kubernetes Benchmark + Polaris workload-posture + 10-rule
manifest static analysis on operator-pinned filesystem snapshots.

Emits OCSF v1.3 Compliance Findings (`class_uid 2003`) — re-uses F.3's
schema verbatim (D.5 set the precedent). Discriminator on
`finding_info.types[0]`: `cspm_k8s_cis` / `cspm_k8s_polaris` /
`cspm_k8s_manifest`.

Three-feed shape (offline filesystem mode in v0.1):

- kube-bench JSON output (CIS Kubernetes Benchmark)
- Polaris JSON output (workload posture)
- Manifest directory (flat *.yaml; runs the bundled 10-rule analyser)

Six-stage pipeline:

  INGEST → NORMALIZE → SCORE → DEDUP → SUMMARIZE → HANDOFF

The dedup stage (new vs D.5) collapses overlapping checks from
kube-bench + Polaris + manifest sources via composite key
`(rule_id_or_control_id, namespace, workload, 5min_bucket)`.

Live `kubernetes-client` + Helm chart inventory deferred to Phase 1c.
v0.1 reads operator-pinned filesystem snapshots — mirrors F.3
(LocalStack) + D.4 + D.5 patterns.
"""

from __future__ import annotations

__version__ = "0.1.0"
