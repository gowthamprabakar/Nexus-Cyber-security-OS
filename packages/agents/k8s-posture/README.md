# `nexus-k8s-posture-agent`

Kubernetes Posture Agent — D.6; **fourth Phase-1b agent**; **ninth under [ADR-007](../../../docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)** (F.3 / D.1 / D.2 / D.3 / F.6 / D.7 / D.4 / D.5 / **D.6**). **Closes the Phase-1b detection track.**

> **Status:** v0.1 bootstrap. See the [D.6 plan](../../../docs/superpowers/plans/2026-05-13-d-6-kubernetes-posture.md) for the 16-task execution roadmap. This README is replaced with the full operator-facing content at Task 16.

## What it does (target)

Three-feed offline analysis:

- **kube-bench** — CIS Kubernetes Benchmark JSON output (`kube-bench --json`)
- **Polaris** — workload posture JSON output (`polaris audit --format=json`)
- **Manifest directory** — flat `*.yaml` files; runs the bundled 10-rule analyser

Emits OCSF v1.3 Compliance Findings (`class_uid 2003`) — re-uses F.3's schema (per D.5's precedent). Phase 1c adds live `kubernetes-client` + Helm chart inventory.

## License

BSL 1.1 per [ADR-001](../../../docs/_meta/decisions/ADR-001-monorepo-bootstrap.md).
