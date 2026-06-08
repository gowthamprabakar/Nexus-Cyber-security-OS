#!/usr/bin/env bash
# verify-charter-live-postgres.sh — one-command runner for charter.memory's
# real-Postgres integration suite (the keystone that `ci.yml` skips). Brings up
# a clean pgvector Postgres, syncs the exact deps the suite needs (incl. the
# psycopg2 the alembic sync env requires), and runs the live tests.
#
#   bash scripts/verify-charter-live-postgres.sh
#
# Mirrors the `charter-f5-live.yml` CI lane locally.
#
# Expected once the tracked multi-bug substrate cycle lands: 6 passed.
# Today on main it is NOT green — three pre-existing substrate bugs block it
# (LTREE attribute-error, pgvector cosine_distance, RLS not FORCEd + superuser
# role bypass). See the multi-tenant-RLS substrate brainstorm.
#
# Environment requirements (diagnosed):
#   - Docker daemon running.
#   - Port 5432 free (this script stops a homebrew Postgres holding it).
#   - Deps come from `uv sync` (NOT `uv pip install --upgrade`, which uv treats
#     as already-satisfied in a workspace). psycopg2-binary is declared in the
#     root [dependency-groups] dev group; `uv sync` brings it in.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="docker/docker-compose.dev.yml"
TEST_PATH="packages/charter/tests/integration/test_memory_live_postgres.py"

echo "==> [1/5] Free port 5432 (stop any native Postgres holding it)"
if command -v brew >/dev/null 2>&1; then
  for svc in postgresql@15 postgresql@16 postgresql; do
    brew services stop "$svc" >/dev/null 2>&1 || true
  done
fi
if lsof -nP -iTCP:5432 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "    WARNING: something is still listening on :5432 — the container may"
  echo "    fail to bind. Holder:"
  lsof -nP -iTCP:5432 -sTCP:LISTEN || true
fi

echo "==> [2/5] Verify Docker is running"
if ! docker info >/dev/null 2>&1; then
  echo "    ERROR: Docker daemon not reachable. Start Docker Desktop and retry." >&2
  exit 2
fi

echo "==> [3/5] Bring up pgvector Postgres (clean slate)"
# Remove the bind-mounted data dir so stale creds/schema don't poison the run.
docker compose -f "$COMPOSE_FILE" rm -sf postgres >/dev/null 2>&1 || true
rm -rf ./.data/postgres 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d postgres
echo -n "    waiting for healthy"
for _ in $(seq 1 40); do
  if docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U nexus >/dev/null 2>&1; then
    echo " — ready."
    break
  fi
  echo -n "."; sleep 2
done

echo "==> [4/5] Sync deps (correct versions from uv.lock, incl. psycopg2 via dev group)"
uv sync --all-extras --all-packages

echo "==> [5/5] Run the live charter suite (NEXUS_LIVE_POSTGRES=1)"
set +e
NEXUS_LIVE_POSTGRES=1 uv run pytest "$TEST_PATH" -v
status=$?
set -e

echo
if [ "$status" -eq 0 ]; then
  echo "RESULT: ✅ charter live-Postgres suite PASSED."
else
  echo "RESULT: ❌ suite FAILED (exit $status) — see output above."
  echo "        (Expected on main today until the multi-bug substrate cycle lands.)"
fi
echo "(Tear down with: docker compose -f $COMPOSE_FILE down)"
exit "$status"
