"""G1 skill adoption tracker — Task 5 (adoption-axis computation).

Read-only consumer of sidecar ``run-events.jsonl`` files.  Computes
per-skill adoption metrics from ``agent.skill.loaded`` events.

**Leaf-module discipline (per G1-Q6):** imports ONLY from
``meta_harness.schemas``, stdlib, and pydantic.  Does NOT import from
``skill_lifecycle``, ``skill_writer``, ``skill_eval_gate``,
``skill_approval``, or any future effectiveness-computation modules.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from meta_harness.schemas import _MAX_AGENT_ID_LENGTH, _MAX_SKILL_ID_LENGTH, _MAX_TENANT_ID_LENGTH

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Adoption metrics model
# ---------------------------------------------------------------------------


class AdoptionMetrics(BaseModel):
    """Per-skill adoption-axis metrics computed from sidecar JSONL.

    Confidence grows toward 1.0 as ``load_count`` increases:
    ``confidence = min(1.0, load_count / 10.0)``.  Zero loads → zero
    confidence, ten or more loads → full confidence on the adoption axis.
    """

    model_config = ConfigDict(frozen=True)

    skill_id: str = Field(min_length=1, max_length=_MAX_SKILL_ID_LENGTH)
    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    tenant_id: str = Field(default="default", min_length=1, max_length=_MAX_TENANT_ID_LENGTH)
    load_count: int = Field(default=0, ge=0)
    unique_runs: int = Field(default=0, ge=0)
    unique_agents: int = Field(default=0, ge=0)
    first_loaded_at: datetime | None = None
    last_loaded_at: datetime | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Sidecar path resolution
# ---------------------------------------------------------------------------


def _sidecar_path(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
) -> Path:
    """Canonical sidecar path per the G1 plan doc storage convention."""
    return workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "run-events.jsonl"


# ---------------------------------------------------------------------------
# Sidecar reader
# ---------------------------------------------------------------------------


def read_run_events(
    agent_id: str,
    skill_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
) -> Iterator[dict[str, object]]:
    """Yield every sidecar event for a given (agent, skill, tenant) triple.

    Reads the ``run-events.jsonl`` file line by line.  Malformed JSON
    lines are logged at warning level and skipped — they do not crash
    the generator (per CF #2 / WI-4 graceful degradation).
    """
    path = _sidecar_path(workspace_root, agent_id, skill_id)
    if not path.is_file():
        return
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                _logger.warning("Skipping malformed JSONL line %d in %s", lineno, path)
                continue
            # Tenant filter: only yield records matching the requested tenant.
            record_tenant = record.get("tenant_id", "default")
            if record_tenant != tenant_id:
                continue
            yield record


# ---------------------------------------------------------------------------
# Adoption metrics computation
# ---------------------------------------------------------------------------


def compute_adoption_metrics(
    skill_id: str,
    agent_id: str,
    *,
    workspace_root: Path,
    tenant_id: str = "default",
) -> AdoptionMetrics:
    """Compute adoption-axis metrics from sidecar ``run-events.jsonl``.

    Reads all sidecar events for the given (agent, skill, tenant) triple,
    filters to ``agent.skill.loaded`` events, and computes aggregate
    metrics: load count, unique runs, unique agents, first/last load
    timestamp, and confidence.

    Returns ``AdoptionMetrics`` with ``load_count=0`` and
    ``confidence=0.0`` when the sidecar file is missing or contains no
    matching events (WI-4 backwards-compat graceful degradation).
    """
    load_count = 0
    unique_runs: set[str] = set()
    unique_agents: set[str] = set()
    first_loaded_at: datetime | None = None
    last_loaded_at: datetime | None = None

    for record in read_run_events(
        agent_id=agent_id,
        skill_id=skill_id,
        workspace_root=workspace_root,
        tenant_id=tenant_id,
    ):
        action = record.get("action", "")
        if action != "agent.skill.loaded":
            continue
        load_count += 1

        run_id = record.get("run_id")
        if isinstance(run_id, str):
            unique_runs.add(run_id)

        record_agent = record.get("agent_id")
        if isinstance(record_agent, str):
            unique_agents.add(record_agent)

        loaded_str = record.get("loaded_at")
        if isinstance(loaded_str, str):
            try:
                ts = datetime.fromisoformat(loaded_str)
            except ValueError:
                continue
            if first_loaded_at is None or ts < first_loaded_at:
                first_loaded_at = ts
            if last_loaded_at is None or ts > last_loaded_at:
                last_loaded_at = ts

    confidence = min(1.0, load_count / 10.0)
    return AdoptionMetrics(
        skill_id=skill_id,
        agent_id=agent_id,
        tenant_id=tenant_id,
        load_count=load_count,
        unique_runs=len(unique_runs),
        unique_agents=len(unique_agents),
        first_loaded_at=first_loaded_at,
        last_loaded_at=last_loaded_at,
        confidence=confidence,
    )


__all__ = [
    "AdoptionMetrics",
    "compute_adoption_metrics",
    "read_run_events",
]
