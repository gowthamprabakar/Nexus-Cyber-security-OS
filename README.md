# Nexus Cyber OS

Autonomous cloud security platform with 18 AI agents, edge deployment, and three-tier remediation.

## Quick start

```bash
# Bring up local infra
docker compose -f docker/docker-compose.dev.yml up -d

# Install dependencies
pnpm install
uv sync

# Run all tests
pnpm test
```

## Repo layout

- `packages/charter/` — runtime charter (Apache 2.0, open source)
- `packages/eval-framework/` — eval suite tooling (Apache 2.0, open source)
- `packages/agents/` — the 18 production agents (proprietary BSL)
- `packages/control-plane/` — SaaS control plane (proprietary BSL)
- `packages/edge/` — edge agent runtime (proprietary BSL)
- `packages/console/` — Next.js customer console (proprietary BSL)
- `packages/content-packs/` — vertical content packs (proprietary BSL)
- `docs/` — strategy, architecture, agent specs, runbooks, plans

## Documentation

- [Strategy & PRD](docs/strategy/)
- [Architecture & Charter](docs/architecture/)
- [Agent specifications](docs/agents/)
- [Build roadmap](docs/superpowers/plans/2026-05-08-build-roadmap.md)
- [Glossary](docs/_meta/glossary.md)
- [ADR index](docs/_meta/decisions/)

## License

Open-source packages (charter, eval-framework): Apache 2.0 — see [LICENSE-APACHE](LICENSE-APACHE).

All other packages: Business Source License 1.1 — see [LICENSE-BSL](LICENSE-BSL). Production use requires a commercial license. Free for evaluation, R&D, and academic use.
