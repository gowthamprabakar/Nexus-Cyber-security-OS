"""Skill deprecation — Hermes Phase 5 (dual-trigger + sunset period).

A deployed skill should not live forever. Two independent triggers flag a skill for deprecation
(brainstorm Q6 — dual-trigger, OR semantics: *either* fires):

* **time** (:data:`DeprecationTrigger.STALE_AGE`) — the skill has been deployed longer than
  :data:`DEFAULT_MAX_AGE_DAYS`. A rotation/staleness policy: old skills get re-examined even if
  still passing.
* **performance** (:data:`DeprecationTrigger.LOW_EFFECTIVENESS`) — the skill's measured
  effectiveness ``global_score`` is below :data:`DEFAULT_MIN_EFFECTIVENESS` (with non-zero
  confidence — an unscored skill is never deprecated on performance grounds).

A flagged skill enters a **sunset period** (:data:`DEFAULT_SUNSET_DAYS`) during which it is
:data:`DeprecationPhase.SUNSET` — still live, but on notice, giving a replacement time to deploy.
Once the sunset elapses it becomes :data:`DeprecationPhase.EXPIRED` (recommended for archival).
If every trigger clears before the sunset elapses (e.g. effectiveness recovers) the flag is
dropped and the skill returns to :data:`DeprecationPhase.ACTIVE`.

**Advisory only.** This module never archives or removes a skill — exactly like the F.6 audit
agent never auto-repairs and A.1 defaults to recommend. It produces :class:`DeprecationDecision`
records; acting on an ``EXPIRED`` recommendation (removing the skill from the registry) is a
deliberate operator/driver action. So the controller is safe to run continuously.

**Age anchoring (honest limitation).** No deploy timestamp is persisted with deployed skills, so
age is measured from when this controller *first observed* the skill (stamped into its own state
sidecar). For skills already deployed before the controller first ran, age is therefore a
*lower bound* on true deployment age — conservative (never deprecates earlier than warranted).

Leaf-module discipline: imports only ``effectiveness_store`` + stdlib.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path

from meta_harness.effectiveness_store import list_deployed_skills_with_scores

_LOG = logging.getLogger(__name__)

DEFAULT_MAX_AGE_DAYS = 90
DEFAULT_MIN_EFFECTIVENESS = 0.4
DEFAULT_SUNSET_DAYS = 14

_STATE_DIRNAME = "skill-deprecation"
_STATE_FILENAME = "state.json"


class DeprecationTrigger(Enum):
    """Why a skill was flagged for deprecation (dual-trigger, Q6)."""

    STALE_AGE = "stale_age"
    LOW_EFFECTIVENESS = "low_effectiveness"


class DeprecationPhase(Enum):
    """Lifecycle phase of a deployed skill under the deprecation policy."""

    ACTIVE = "active"  # no trigger fired (or a prior flag cleared)
    SUNSET = "sunset"  # flagged; within the sunset window — still live, on notice
    EXPIRED = "expired"  # sunset elapsed — recommended for archival (advisory)


@dataclass(frozen=True, slots=True)
class DeprecationDecision:
    """Per-skill deprecation verdict."""

    agent_id: str
    skill_id: str
    phase: DeprecationPhase
    triggers: tuple[DeprecationTrigger, ...]
    reason: str
    flagged_at: datetime | None
    sunset_until: datetime | None


def _detect_triggers(
    *,
    age_days: float | None,
    effectiveness: float | None,
    confidence: float,
    max_age_days: int,
    min_effectiveness: float,
) -> tuple[DeprecationTrigger, ...]:
    triggers: list[DeprecationTrigger] = []
    if age_days is not None and age_days >= max_age_days:
        triggers.append(DeprecationTrigger.STALE_AGE)
    if effectiveness is not None and confidence > 0.0 and effectiveness < min_effectiveness:
        triggers.append(DeprecationTrigger.LOW_EFFECTIVENESS)
    return tuple(triggers)


def evaluate_skill_deprecation(
    *,
    agent_id: str,
    skill_id: str,
    age_days: float | None,
    effectiveness: float | None,
    confidence: float,
    flagged_at: datetime | None,
    now: datetime,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    min_effectiveness: float = DEFAULT_MIN_EFFECTIVENESS,
    sunset_days: int = DEFAULT_SUNSET_DAYS,
) -> DeprecationDecision:
    """Pure dual-trigger + sunset evaluation for one skill.

    ``flagged_at`` is the persisted first-flagged timestamp (``None`` = not currently flagged).
    Returns the new :class:`DeprecationDecision`; the caller persists ``flagged_at`` from it.
    """
    triggers = _detect_triggers(
        age_days=age_days,
        effectiveness=effectiveness,
        confidence=confidence,
        max_age_days=max_age_days,
        min_effectiveness=min_effectiveness,
    )
    if not triggers:
        # No trigger → active. Any prior flag is dropped (e.g. effectiveness recovered).
        return DeprecationDecision(
            agent_id=agent_id,
            skill_id=skill_id,
            phase=DeprecationPhase.ACTIVE,
            triggers=(),
            reason="no deprecation trigger",
            flagged_at=None,
            sunset_until=None,
        )
    first_flagged = flagged_at or now  # newly flagged → start the sunset clock now
    sunset_until = first_flagged + timedelta(days=sunset_days)
    phase = DeprecationPhase.EXPIRED if now >= sunset_until else DeprecationPhase.SUNSET
    names = ", ".join(t.value for t in triggers)
    if phase is DeprecationPhase.EXPIRED:
        reason = f"sunset elapsed ({names}); recommend archival"
    else:
        reason = f"flagged ({names}); in sunset until {sunset_until.date().isoformat()}"
    return DeprecationDecision(
        agent_id=agent_id,
        skill_id=skill_id,
        phase=phase,
        triggers=triggers,
        reason=reason,
        flagged_at=first_flagged,
        sunset_until=sunset_until,
    )


class SkillDeprecationController:
    """Evaluates deprecation across all deployed skills; persists flag/observation state.

    Advisory: produces decisions; never archives. State sidecar lives under
    ``<workspace>/.nexus/skill-deprecation/state.json`` (mirrors the cadence controller).
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        tenant_id: str = "default",
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
        min_effectiveness: float = DEFAULT_MIN_EFFECTIVENESS,
        sunset_days: int = DEFAULT_SUNSET_DAYS,
    ) -> None:
        self._workspace_root = Path(workspace_root)
        self._tenant_id = tenant_id
        self._max_age_days = max_age_days
        self._min_effectiveness = min_effectiveness
        self._sunset_days = sunset_days

    def _state_path(self) -> Path:
        return self._workspace_root / ".nexus" / _STATE_DIRNAME / _STATE_FILENAME

    def _load_state(self) -> dict[str, dict[str, str]]:
        path = self._state_path()
        if not path.is_file():
            return {}
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}

    def _write_state(self, state: dict[str, dict[str, str]]) -> None:
        path = self._state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _key(agent_id: str, skill_id: str) -> str:
        return f"{agent_id}:{skill_id}"

    def evaluate_all(self, *, now: datetime | None = None) -> list[DeprecationDecision]:
        """Evaluate every deployed skill; persist first-observation + flag state.

        Age is measured from each skill's recorded first-observation timestamp (stamped on the
        first evaluation that sees it). Returns one decision per deployed skill.
        """
        now = now or datetime.now(UTC)
        state = self._load_state()
        decisions: list[DeprecationDecision] = []

        seen_keys: set[str] = set()
        for agent_id, skill_id, score in list_deployed_skills_with_scores(
            self._workspace_root, self._tenant_id
        ):
            key = self._key(agent_id, skill_id)
            seen_keys.add(key)
            entry = state.get(key, {})
            first_observed_raw = entry.get("first_observed_at")
            first_observed = (
                datetime.fromisoformat(first_observed_raw) if first_observed_raw else now
            )
            flagged_raw = entry.get("flagged_at")
            flagged_at = datetime.fromisoformat(flagged_raw) if flagged_raw else None
            age_days = (now - first_observed).total_seconds() / 86400.0

            decision = evaluate_skill_deprecation(
                agent_id=agent_id,
                skill_id=skill_id,
                age_days=age_days,
                effectiveness=score.global_score if score else None,
                confidence=score.confidence if score else 0.0,
                flagged_at=flagged_at,
                now=now,
                max_age_days=self._max_age_days,
                min_effectiveness=self._min_effectiveness,
                sunset_days=self._sunset_days,
            )
            decisions.append(decision)
            new_entry: dict[str, str] = {"first_observed_at": first_observed.isoformat()}
            if decision.flagged_at is not None:
                new_entry["flagged_at"] = decision.flagged_at.isoformat()
            state[key] = new_entry

        # Drop state for skills no longer deployed (cleanliness).
        for stale_key in set(state) - seen_keys:
            del state[stale_key]

        self._write_state(state)
        for d in decisions:
            if d.phase is not DeprecationPhase.ACTIVE:
                _LOG.info(
                    "skill_deprecation.flagged agent_id=%s skill_id=%s phase=%s reason=%s",
                    d.agent_id,
                    d.skill_id,
                    d.phase.value,
                    d.reason,
                )
        return decisions


__all__ = [
    "DEFAULT_MAX_AGE_DAYS",
    "DEFAULT_MIN_EFFECTIVENESS",
    "DEFAULT_SUNSET_DAYS",
    "DeprecationDecision",
    "DeprecationPhase",
    "DeprecationTrigger",
    "SkillDeprecationController",
    "evaluate_skill_deprecation",
]
