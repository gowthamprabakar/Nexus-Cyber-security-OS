# Memory engines bootstrap — operator runbook

Owner: charter on-call · Audience: an operator bringing up the `charter.memory` Postgres backend (dev, staging, or prod) · Last reviewed: 2026-05-12.

This runbook covers the **first-time bootstrap** of the three memory engines (`EpisodicStore`, `ProceduralStore`, `SemanticStore`) against a Postgres 16 + pgvector cluster. After it's complete, every Nexus agent that wires a `MemoryService` against `NEXUS_DATABASE_URL` can read and write the four memory tables under per-tenant RLS.

> **Status:** v0.1. Phase 1c will move the alembic step into a Terraform / Pulumi module that materialises the database, the role, and the secret in one apply. Today it's manual on purpose — same reason as the F.4 Auth0 runbook: bootstrapping while the configuration shape is still settling avoids re-IaCing twice.

---

## Prerequisites

- Postgres 16 with the `vector` and `ltree` extensions available. The dev compose at `docker/docker-compose.dev.yml` bundles `pgvector/pgvector:pg16`, which ships both preinstalled.
- A Postgres role that owns the target database (it must hold `CREATE EXTENSION` privilege for the bootstrap; you can revoke it afterwards).
- This monorepo checkout with `uv sync` clean.
- The `psql` CLI available — every command below uses it directly so the steps work whether you're in dev compose, Cloud SQL, RDS, or self-hosted.

---

## 1. Bring up the Postgres backend

### 1a. Local dev (Docker Compose)

```bash
docker compose -f docker/docker-compose.dev.yml up -d postgres
docker compose -f docker/docker-compose.dev.yml exec -T postgres \
    pg_isready -U nexus
```

The default credentials are `nexus / nexus_dev`, and the default database `nexus`. The compose file maps port `5432` to your host.

### 1b. Cloud / production

Stand up Postgres 16 + pgvector through your provider. Two options:

1. **Cloud SQL for Postgres 16** — enable `pgvector` and `ltree` via the **Extensions** tab in the GCP console, or in Terraform:

   ```hcl
   resource "google_sql_database_instance" "memory" {
     database_version = "POSTGRES_16"
     settings {
       database_flags { name = "cloudsql.iam_authentication" value = "on" }
     }
   }
   # then in psql against the instance:
   # CREATE EXTENSION IF NOT EXISTS vector;
   # CREATE EXTENSION IF NOT EXISTS ltree;
   ```

2. **AWS RDS for Postgres 16** — pgvector is available from Postgres 15.5+. Apply via parameter group:

   ```bash
   aws rds modify-db-parameter-group \
     --db-parameter-group-name nexus-memory-pg16 \
     --parameters "ParameterName=shared_preload_libraries,ParameterValue=vector,ApplyMethod=pending-reboot"
   ```

   then in psql: `CREATE EXTENSION vector; CREATE EXTENSION ltree;`

> **Why not self-hosted Postgres?** Phase 1a optimises for "one button, one bill"; Phase 2 GA hardening considers self-host once the storage / IOPS pattern is well-characterised.

---

## 2. Create the target database

Once Postgres is reachable, create the database the memory engines will own:

```bash
psql "postgresql://nexus:nexus_dev@localhost:5432/postgres" \
     -c "CREATE DATABASE nexus_memory"
```

For non-dev environments, vary the DB name and credentials per your environment convention. **Do not reuse `nexus_control_plane`** — F.4's alembic head writes to `alembic_version` and F.5's writes to `alembic_version_memory`; the two heads coexist on the same Postgres but they should live in their own databases for blast-radius reasons.

---

## 3. Run the alembic migration

The memory schema lives in `packages/charter/alembic/`. Drive it through alembic so the indexes (pgvector ivfflat, JSONB GIN, LTREE GiST) and the Task-7 RLS policies all land together:

```bash
NEXUS_DATABASE_URL="postgresql+psycopg2://nexus:nexus_dev@localhost:5432/nexus_memory" \
    uv run alembic -c packages/charter/alembic.ini upgrade head
```

After it returns cleanly, the database has:

- The four tables: `episodes`, `playbooks`, `entities`, `relationships`.
- The pgvector + ltree extensions (created idempotently inside the upgrade).
- All production indexes — including the Postgres-only `ix_episodes_payload_gin`, `ix_episodes_embedding_ivf`, and `ix_playbooks_path_gist`.
- Row-Level Security enabled on every memory table with a `tenant_isolation` policy that reads `current_setting('app.tenant_id', true)`.
- A distinct version table `alembic_version_memory` so the head doesn't collide with control-plane's `alembic_version`.

To roll back (carefully — this drops the tables):

```bash
NEXUS_DATABASE_URL="postgresql+psycopg2://nexus:nexus_dev@localhost:5432/nexus_memory" \
    uv run alembic -c packages/charter/alembic.ini downgrade base
```

---

## 4. Smoke-test the bootstrap

Verify the extensions, tables, and RLS policies all landed.

```bash
psql "postgresql://nexus:nexus_dev@localhost:5432/nexus_memory" \
    -c "SELECT extname FROM pg_extension WHERE extname IN ('vector', 'ltree')"
# expected: 2 rows (vector, ltree)

psql "postgresql://nexus:nexus_dev@localhost:5432/nexus_memory" \
    -c "\dt"
# expected: 4 tables + alembic_version_memory

psql "postgresql://nexus:nexus_dev@localhost:5432/nexus_memory" -c "
    SELECT tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
    ORDER BY tablename"
# expected: 4 rows — one tenant_isolation policy per memory table
```

If any of those returns fewer rows than expected, the alembic upgrade did not complete. Re-run step 3.

---

## 5. Smoke-test a read/write round-trip

The fastest end-to-end check is the live integration test (F.5 Task 10). It boots a `MemoryService`, inserts on all three engines, exercises pgvector ANN, and verifies RLS isolates two tenants:

```bash
NEXUS_LIVE_POSTGRES=1 \
    uv run pytest packages/charter/tests/integration/test_memory_live_postgres.py -v
```

Expected: 6 tests pass. If `test_rls_isolates_tenants_on_episodes` fails, RLS is not enforced — most likely cause is a Postgres role configured as `BYPASSRLS` (superuser, or a role with the bypass attribute). Memory writes must not run as superuser in production; create a dedicated role:

```sql
CREATE ROLE nexus_memory_app NOINHERIT LOGIN PASSWORD '<from secrets>';
GRANT CONNECT ON DATABASE nexus_memory TO nexus_memory_app;
GRANT USAGE ON SCHEMA public TO nexus_memory_app;
GRANT ALL ON ALL TABLES IN SCHEMA public TO nexus_memory_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nexus_memory_app;
-- crucial: do NOT grant BYPASSRLS.
```

Application connections then use the `nexus_memory_app` DSN, not the bootstrap admin DSN.

---

## 6. Wire `MemoryService` into agent code

Once the bootstrap is healthy, an agent constructs a `MemoryService` against the live URL:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from charter.memory import FakeEmbeddingProvider, MemoryService

engine = create_async_engine(
    "postgresql+asyncpg://nexus_memory_app:<pw>@<host>:5432/nexus_memory",
)
memory = MemoryService(
    session_factory=async_sessionmaker(engine, expire_on_commit=False),
    embedder=FakeEmbeddingProvider(),       # Phase 1b: swap for OpenAI / Anthropic
    audit_log=charter_ctx.audit,            # optional, but recommended
)

async with memory.session(tenant_id=request.tenant_id):
    episode_id = await memory.append_event(
        tenant_id=request.tenant_id,
        correlation_id=charter_ctx.correlation_id,
        agent_id="cloud_posture",
        action="finding.created",
        payload={"text": finding.title, "severity": finding.severity},
    )
```

The `session(tenant_id=...)` context manager runs `SET LOCAL app.tenant_id` inside the same transaction, so RLS scopes every query without the agent code having to thread `WHERE tenant_id = ?` manually.

---

## 7. Production hardening checklist

Before flipping a memory-enabled agent on for a customer:

- [ ] **Connection pooling.** Use PgBouncer in `transaction` mode in front of the cluster — the per-session `SET LOCAL` works correctly under transaction-mode pooling because it's scoped to the txn. Session-mode pooling is fine but burns connections; statement-mode pooling **breaks** `SET LOCAL` and must not be used.
- [ ] **Backups.** Cloud SQL / RDS automated backups daily with point-in-time recovery for at least 7 days. Phase 1b extends to 30 days.
- [ ] **Connection limits.** Set `max_connections` to a number that fits your PgBouncer pool size × replica count.
- [ ] **Monitoring.** Watch `pg_stat_activity`, `pg_stat_user_tables.n_tup_ins`, and the ivfflat index hit ratio. Phase 1b ships a Grafana dashboard; v0.1 is `psql`.
- [ ] **Vacuum.** The `episodes` table is append-only and high-volume — confirm autovacuum thresholds (default `autovacuum_vacuum_scale_factor=0.2` is fine for v0.1).
- [ ] **ivfflat tuning.** The baseline uses `lists = 100`, suitable for ~1M episodes per tenant. After your first 30 days of production volume, recompute with `floor(sqrt(N))` where N is the typical episode count and reissue the index with the new value.

---

## 8. Troubleshooting

| Symptom                                                            | Likely cause                                                                | Fix                                                                                                                   |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `alembic upgrade` fails with `extension "vector" is not available` | Image is vanilla `postgres:16`, not `pgvector/pgvector:pg16`.               | Swap the image; re-run step 3. Dev: `docker compose pull postgres && docker compose up -d --force-recreate postgres`. |
| `permission denied to create extension`                            | Bootstrap role lacks `CREATE EXTENSION`.                                    | Grant `CREATEROLE, CREATEDB` to the bootstrap role; revoke after step 3.                                              |
| `current_setting('app.tenant_id', true) IS NULL` for every query   | Pool runs in statement mode; `SET LOCAL` doesn't persist across statements. | Reconfigure PgBouncer to `transaction` mode.                                                                          |
| `search_similar` returns `[]` even with rows present               | Empty embedding column, or pgvector extension missing on the connected DB.  | `SELECT count(*) FROM episodes WHERE embedding IS NULL`; if non-zero, re-embed and re-write.                          |
| `relation "alembic_version_memory" does not exist`                 | F.5 alembic head was never run; only F.4's was.                             | Re-run step 3 against the correct DB.                                                                                 |

---

## Cross-references

- F.5 plan: [`docs/superpowers/plans/2026-05-11-f-5-memory-engines.md`](../../../docs/superpowers/plans/2026-05-11-f-5-memory-engines.md).
- Migration source: [`packages/charter/alembic/versions/0001_memory_baseline.py`](../alembic/versions/0001_memory_baseline.py), [`0002_memory_rls.py`](../alembic/versions/0002_memory_rls.py).
- Architecture decision (drafted alongside F.5 Task 12): [`docs/_meta/decisions/ADR-009-memory-architecture.md`](../../../docs/_meta/decisions/ADR-009-memory-architecture.md).
