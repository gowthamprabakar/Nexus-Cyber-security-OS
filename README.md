# Nexus Cyber OS

**An autonomous cloud-security operating system.** 18 AI agents under a runtime charter, a shared substrate of typed memory + hash-chained audit + tenant-scoped Postgres, evaluable via a framework that gates every NLAH rewrite. Phase 1a foundations shipped 2026-05-12; five agents in production today; the remainder shipping monthly on the reference template.

```
Phase 1a foundations  ✅ F.1 charter   ✅ F.2 eval-framework   ✅ F.3 cloud-posture (reference NLAH)
                       ✅ F.4 auth + tenants   ✅ F.5 memory engines   ✅ F.6 audit agent

Agents shipped         ✅ F.3 Cloud Posture   ✅ D.1 Vulnerability   ✅ D.2 Identity
                       ✅ D.3 Runtime Threat  ✅ F.6 Audit Agent     ⬜ 13 remaining

Test suite             1,168 passing / 11 opt-in skipped     mypy --strict clean (119 files)
                       96% coverage on shipped agent packages
ADR-007 reference NLAH v1.3 — five agents converged on the template; LLM adapter + NLAH loader
                       hoisted into charter substrate; F.6 introduced the always-on agent class
```

---

## What it does

Nexus is the platform layer for autonomous cloud security. A supervisor delegates a security task to a specialised agent under a signed `ExecutionContract` — budget envelope, tool whitelist, audit chain. The agent runs to completion, emits OCSF v1.3 findings, persists state to typed memory engines, and writes a hash-chained audit trail every other agent (and any external auditor) can verify.

Today's five shipped agents cover:

| Agent              | Pillar | OCSF class         | Capability                                                                 |
| ------------------ | ------ | ------------------ | -------------------------------------------------------------------------- |
| **Cloud Posture**  | F.3    | 2003 Compliance    | Prowler-driven CSPM scans across AWS/Azure/GCP                             |
| **Vulnerability**  | D.1    | 2002 Vulnerability | Trivy-driven image + filesystem vulnerability scans                        |
| **Identity**       | D.2    | 2004 Detection     | CIEM — IAM permission graphs + Access Analyzer cross-confirmation          |
| **Runtime Threat** | D.3    | 2004 Detection     | CWPP — Falco / Tracee / OSQuery alert normalisation                        |
| **Audit Agent**    | F.6    | 6003 API Activity  | Hash-chained audit query surface; the only agent the others cannot disable |

The next 13 agents (D.4 Network Threat, D.5–D.6 CSPM extensions, D.7 Investigation, A.1–A.3 remediation, A.4 Meta-Harness, A.5–A.7 self-evolution, D.12 Curiosity, D.13–D.14 vertical packs) are pure pattern application against the now-stable substrate.

---

## Architecture at a glance

```
                                            ┌──────────────────────────────┐
   ExecutionContract (signed)      ────────►│ Charter (F.1)                │
                                            │  budget envelope             │
                                            │  tool whitelist              │
                                            │  audit chain (SHA-256)       │
                                            └───────────┬──────────────────┘
                                                        │
                                                        ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │ Agent (one of 18; ADR-007 reference NLAH template)                     │
   │                                                                        │
   │  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐    │
   │  │ Async tools      │   │ NLAH bundle      │   │ LLM adapter      │    │
   │  │ (ADR-005)        │   │ (charter hoist,  │   │ (charter hoist,  │    │
   │  │                  │   │  ADR-007 v1.2)   │   │  ADR-007 v1.1)   │    │
   │  └──────────────────┘   └──────────────────┘   └──────────────────┘    │
   │                                                                        │
   │  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐    │
   │  │ OCSF schemas     │   │ Eval-runner      │   │ CLI              │    │
   │  │ (pydantic 2.9)   │   │ (entry-point)    │   │ (eval / run /…)  │    │
   │  └──────────────────┘   └──────────────────┘   └──────────────────┘    │
   └────────────────────────────────────────────────────────────────────────┘
                                                        │
                                                        ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │ Substrate (shared by every agent)                                      │
   │                                                                        │
   │  charter.memory (F.5)        control_plane.auth (F.4)   F.6 audit      │
   │  ─ episodic   pgvector       ─ Auth0 SSO + MFA          ─ audit_events │
   │  ─ procedural LTREE          ─ tenants + users          ─ chain verify │
   │  ─ semantic   recursive CTE  ─ tenant ULID propagation  ─ RLS          │
   │                                                                        │
   │  Postgres 16 + pgvector + ltree · per-tenant RLS                       │
   │  alembic_version_memory (F.5/F.6)  ·  alembic_version (F.4)            │
   └────────────────────────────────────────────────────────────────────────┘
                                                        │
                                                        ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │ Eval framework (F.2, ADR-008)                                          │
   │  ─ YAML cases per agent (10 each in v0.1; 100 each at GA)              │
   │  ─ eval-framework {run, compare, gate}  ·  per-agent EvalRunner        │
   │  ─ NLAH rewrites can't merge until the gate is green                   │
   └────────────────────────────────────────────────────────────────────────┘
```

Every load-bearing decision is documented in an ADR. See [`docs/_meta/decisions/`](docs/_meta/decisions/).

---

## Quick start

### Run the existing test suite (no infra needed)

```bash
uv sync --all-packages --all-extras
uv run pytest -q                   # 1,168 passing in <10s
uv run mypy                        # strict; 119 source files
uv run ruff check packages/
```

### Run an agent's evals

```bash
uv run cloud-posture-agent eval packages/agents/cloud-posture/eval/cases   # 10/10
uv run vulnerability-agent eval packages/agents/vulnerability/eval/cases   # 10/10
uv run identity-agent eval packages/agents/identity/eval/cases             # 10/10
uv run runtime-threat-agent eval packages/agents/runtime-threat/eval/cases # 10/10
uv run audit-agent eval packages/agents/audit/eval/cases                   # 10/10
```

Or through the eval framework:

```bash
uv run eval-framework run --runner cloud_posture --cases <dir>
uv run eval-framework gate --suite <suite-dir> --config min_pass_rate=1.0
```

### Bring up the live substrate (Postgres + pgvector)

```bash
docker compose -f docker/docker-compose.dev.yml up -d postgres
# default: nexus/nexus_dev on localhost:5432, image pgvector/pgvector:pg16

# Materialise the F.5 memory schema + F.6 audit table + RLS
NEXUS_DATABASE_URL='postgresql+psycopg2://nexus:nexus_dev@localhost:5432/nexus_memory' \
    uv run alembic -c packages/charter/alembic.ini upgrade head

# Verify (the live integration test runs 6 cases against the real DB)
NEXUS_LIVE_POSTGRES=1 uv run pytest \
    packages/charter/tests/integration/test_memory_live_postgres.py -v
```

Full operator bootstrap: [`packages/charter/runbooks/memory_bootstrap.md`](packages/charter/runbooks/memory_bootstrap.md).

### Query the audit chain

After an agent has run and emitted its `audit.jsonl`:

```bash
uv run audit-agent query \
    --tenant 01HV0T0000000000000000TENA \
    --workspace /tmp/audit-ws \
    --source /var/log/nexus/audit-2026-05-12.jsonl \
    --since 2026-05-01 \
    --action episode_appended \
    --format markdown
```

Exit code 0 = clean; 1 = tooling failure; **2 = chain tamper**. Operator runbook: [`packages/agents/audit/runbooks/audit_query_operator.md`](packages/agents/audit/runbooks/audit_query_operator.md).

---

## Repo layout

```
packages/
├── charter/                         # Runtime charter — Apache 2.0
│   ├── src/charter/
│   │   ├── audit.py                  # Hash-chained AuditLog
│   │   ├── context.py                # Charter context manager (ADR-002)
│   │   ├── llm_adapter.py            # LLMProvider factory (ADR-007 v1.1)
│   │   ├── nlah_loader.py            # NLAH loader (ADR-007 v1.2)
│   │   └── memory/                   # F.5 — three engines + facade
│   │       ├── models.py             # episodes / playbooks / entities / relationships / audit_events
│   │       ├── episodic.py           # pgvector ANN
│   │       ├── procedural.py         # LTREE versioned playbooks
│   │       ├── semantic.py           # BFS knowledge graph
│   │       └── service.py            # MemoryService DI seam
│   ├── alembic/                      # 0001 baseline / 0002 RLS / 0003 audit_events
│   └── runbooks/memory_bootstrap.md  # F.5 operator runbook
│
├── eval-framework/                  # Eval suite tooling — Apache 2.0 (ADR-008)
│   └── src/eval_framework/           # cases / runner / suite / gate / compare
│
├── agents/                          # Per-agent packages — BSL 1.1
│   ├── cloud-posture/                # F.3 — reference NLAH (ADR-007)
│   ├── vulnerability/                # D.1
│   ├── identity/                     # D.2
│   ├── runtime-threat/               # D.3 — first agent on ADR-007 v1.2
│   └── audit/                        # F.6 — first agent on ADR-007 v1.3 (always-on class)
│
├── control-plane/                   # F.4 — Auth0 + tenants — BSL 1.1
│   ├── src/control_plane/
│   │   ├── auth/                     # JWT validation, role mapping
│   │   └── tenants/                  # tenant ULIDs, scoped sessions
│   ├── alembic/                      # 0001 initial tenant + user tables
│   └── runbooks/auth0_tenant_setup.md
│
└── shared/                          # Cross-package primitives — Apache 2.0
    └── src/shared/fabric/            # correlation_id, NexusEnvelope, OCSF wrap/unwrap

docs/
├── _meta/
│   ├── decisions/                    # ADR-001 .. ADR-009
│   ├── glossary.md                   # 18-agent + concept glossary
│   ├── system-readiness-*.md         # rolling readiness reports
│   └── {d3,f5,f6}-verification-*.md  # per-pillar final-verification records
├── strategy/                         # PRD, VISION, market sizing
├── architecture/                     # NexusEnvelope, fabric, OCSF mappings
├── agents/                           # per-agent specifications
└── superpowers/plans/                # task-by-task implementation plans

docker/
└── docker-compose.dev.yml            # postgres (pgvector), timescale, neo4j, nats, redis, localstack
```

---

## Documentation hubs

- **[Strategy + PRD](docs/strategy/)** — what we're building and why
- **[Architecture decisions](docs/_meta/decisions/)** — every load-bearing choice as an ADR (currently 9)
- **[Agent specifications](docs/agents/)** — the 18-agent inventory
- **[Build roadmap](docs/superpowers/plans/2026-05-08-build-roadmap.md)** — multi-phase plan
- **[System readiness](docs/_meta/system-readiness-2026-05-11-1647ist.md)** — rolling snapshot of completion vs ground-zero
- **[Glossary](docs/_meta/glossary.md)** — every concept in one place

### Foundational ADRs

| #   | Title                                     | Status                            |
| --- | ----------------------------------------- | --------------------------------- |
| 001 | Monorepo bootstrap + dual licensing       | accepted                          |
| 002 | Charter as context manager                | accepted                          |
| 003 | LLM provider strategy                     | accepted                          |
| 004 | Fabric layer (NexusEnvelope, OCSF wrap)   | accepted                          |
| 005 | Async tool-wrapper convention             | accepted                          |
| 006 | OpenAI-compatible provider                | accepted                          |
| 007 | **Cloud Posture as reference NLAH**       | accepted (v1.3 — always-on class) |
| 008 | Eval framework architecture               | accepted                          |
| 009 | Memory architecture (Postgres + pgvector) | accepted                          |

### Per-pillar plans + verification records

| Pillar | Plan                                                                                  | Status                         |
| ------ | ------------------------------------------------------------------------------------- | ------------------------------ |
| D.3    | [Runtime Threat Agent](docs/superpowers/plans/2026-05-11-d-3-runtime-threat-agent.md) | ✅ 16/16 (verification record) |
| F.5    | [Memory engines](docs/superpowers/plans/2026-05-11-f-5-memory-engines.md)             | ✅ 12/12 (verification record) |
| F.6    | [Audit Agent](docs/superpowers/plans/2026-05-12-f-6-audit-agent.md)                   | ✅ 16/16 (verification record) |

---

## Roadmap

| Phase  | Window     | Themes                                                                                           |
| ------ | ---------- | ------------------------------------------------------------------------------------------------ |
| **1a** | ✅ closed  | Foundations (F.1–F.6) + 5 agents (F.3, D.1, D.2, D.3, F.6)                                       |
| **1b** | Q3 2026    | Detection agents (D.4 Network Threat, D.5–D.6 CSPM-extensions, D.7 Investigation)                |
| **1c** | Q4 2026    | Remediation track (A.1–A.3) + Meta-Harness (A.4) + streaming ingest + SIEM connectors            |
| **2**  | Q1–Q2 2027 | Edge plane (Go runtime) + frontend (Next.js console) + Neo4j cross-tenant graph + vertical packs |
| **GA** | Q3 2027    | Customer-facing self-service, multi-region read replicas, FedRAMP-High path                      |

The substrate is locked. Track-D / Track-A / Track-S work is now pure pattern application against the stable foundation — each new agent inherits the reference NLAH, the substrate, the eval-runner shape, and the always-on opt-in (if applicable) without inventing them.

---

## Licensing

The repository is dual-licensed per [ADR-001](docs/_meta/decisions/ADR-001-monorepo-bootstrap.md):

| Package family                                         | License               |
| ------------------------------------------------------ | --------------------- |
| `charter`, `eval-framework`, `shared`                  | **Apache 2.0** (open) |
| `agents/*`, `control-plane`, future `edge` / `console` | **BSL 1.1**           |

Apache packages are the substrate — every Nexus build sits on them, and we want them in the open so the community can audit + extend. Files: [`LICENSE-APACHE`](LICENSE-APACHE).

BSL packages are the commercial differentiation — free for evaluation, R&D, and academic use; production use requires a commercial license. Files: [`LICENSE-BSL`](LICENSE-BSL).

The license boundary is enforced at the package level — `packages/charter/pyproject.toml` references `LICENSE-APACHE`; each `packages/agents/*/pyproject.toml` references `LICENSE-BSL`.

---

## Contributing

This is the build-out branch. Public contribution channels open at GA (Q3 2027). Until then, contributions are gated through the Nexus team — open an issue with the proposal first, then a PR against `main` with:

- An ADR if the change touches an architectural seam.
- The relevant per-agent or per-pillar plan updated.
- All gates green (`pytest -q`, `mypy`, `ruff check`, `ruff format --check`).
- A verification record at `docs/_meta/<task>-verification-<date>.md` if the work closes a pillar or agent.

The reference template ([ADR-007](docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md)) is load-bearing. Deltas need explicit justification — see how F.6 added the always-on class in [v1.3](docs/_meta/decisions/ADR-007-cloud-posture-as-reference-agent.md#v13-amendment-2026-05-12---always-on-agent-class) for the pattern.

---

## Status snapshot

```
Phase 1a foundations:    F.1 ✅  F.2 ✅  F.3 ✅  F.4 ✅  F.5 ✅  F.6 ✅    (CLOSED)
Track-D detection:       D.1 ✅  D.2 ✅  D.3 ✅  D.4–D.18 pending
Track-A autonomy:        A.1–A.7 pending
Track-S frontend:        S.1–S.4 pending
Track-E edge plane:      E.1–E.3 pending (Go runtime)

Repo tests:              1,168 passing  /  11 opt-in skipped  (no regressions)
Mypy --strict:           clean across 119 source files
Coverage:                charter.memory 95%  ·  audit 96%  ·  per-agent ≥80%
ADR-007 conformance:     5 agents under v1.0  ·  3 under v1.1  ·  2 under v1.2  ·  1 under v1.3
```

Snapshots refresh on every pillar / agent closure under [`docs/_meta/`](docs/_meta/). The current truth lives in the most recent `system-readiness-*.md` and `*-verification-*.md` files.

— Last updated 2026-05-12, on F.6 Audit Agent closure.
