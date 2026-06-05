"""GEPA metric adapter for G1 effectiveness scoring — v0.2.5 Task 4.

Wraps G1's ``get_effectiveness_score`` for GEPA's ``metric=`` parameter,
honoring the three v0.2.5 brainstorm Q5 policy decisions:

* **(a) SKIP** — when ``get_effectiveness_score`` returns ``None`` *or* a
  score with ``confidence == 0.0``, the adapter returns ``None`` to signal
  "no metric available." GEPA excludes the example from training data;
  skills re-enter the pool once evidence accumulates.
* **(b) MODULATE** — for a valid score, the scalar metric is
  ``global_score x confidence`` (the same composite math G2's persona
  selection uses, keeping selection and optimization consistent).
* **(c) USE operator notes** — operator feedback notes are read from the
  ratings sidecar **once at construction** (compilation-cycle start) and
  cached in memory; the reflection string is
  ``reason + axes breakdown + operator notes``.

Read-only G1 consumer — never writes G1 state, never mutates
``effectiveness_store`` / ``skill_feedback``. CF #2 graceful-degradation:
an unexpected G1 read failure emits ``meta_harness.skill.effectiveness_error``
to the audit chain and returns ``None`` (skip) — effectiveness never breaks
compilation.

Leaf-module discipline: imports only ``effectiveness_store`` (G1 read),
``skill_feedback`` (operator-notes read), ``schemas`` (types),
``charter.audit``, and ``shared.skill_telemetry`` — never from
``skill_lifecycle`` / ``skill_writer`` / ``skill_eval_gate`` /
``skill_approval``.

**Scope (Task 4).** Adapter only. The Stage-7 parallel composer (Task 5),
eval-gate adjudication (Task 6), and compilation cadence (Task 7) consume
this adapter later; no real GEPA compilation runs here.
"""

from __future__ import annotations

import importlib
import traceback
from pathlib import Path
from typing import Any

from charter.audit import AuditLog
from shared.skill_telemetry import ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR

from meta_harness.effectiveness_store import get_effectiveness_score
from meta_harness.schemas import EffectivenessScore
from meta_harness.skill_feedback import read_operator_ratings

_DEPLOYED_SKILLS_DIRNAME = "deployed-skills"
_RATINGS_FILENAME = "operator-ratings.jsonl"


def _score_with_feedback(score: float, feedback: str) -> Any:
    """Wrap (score, feedback) in DSPy's GEPA metric-return type (Q5-c mechanism).

    GEPA's ``GEPAFeedbackMetric`` contract is ``Union[float, ScoreWithFeedback]``
    — a raw ``tuple[float, str]`` crashes DSPy's parallel evaluator
    (``sum(vals)`` → ``int + tuple``). The canonical carrier is
    ``dspy.teleprompt.gepa.gepa_utils.ScoreWithFeedback`` (a ``dspy.Prediction``
    subclass with ``score`` + ``feedback``). That path is semi-internal and GEPA
    is ``@experimental`` in DSPy 3.x, so if it drifts we fall back to the stable
    top-level ``dspy.Prediction(score=, feedback=)`` — functionally identical and
    GEPA-accepted. Imports are gated (``importlib``) per the Task-1 optional-dep
    guard (no literal ``import dspy``/``from dspy`` in meta_harness src).
    """
    try:
        gepa_utils = importlib.import_module("dspy.teleprompt.gepa.gepa_utils")
        return gepa_utils.ScoreWithFeedback(score=score, feedback=feedback)
    except (ImportError, AttributeError):  # pragma: no cover - DSPy path-drift fallback
        dspy = importlib.import_module("dspy")
        return dspy.Prediction(score=score, feedback=feedback)


class GEPAMetricAdapter:
    """Wrap the G1 effectiveness API for GEPA's ``metric=`` parameter.

    One adapter is constructed per compilation cycle for one ``agent_id``.
    Operator notes are primed into an in-memory cache at construction
    (Q5-c) and live for the adapter's lifetime; a fresh adapter is built
    for each cycle, so the cache is implicitly invalidated per cycle.
    """

    def __init__(
        self,
        agent_id: str,
        *,
        workspace_root: Path,
        audit_log: AuditLog,
        tenant_id: str = "default",
    ) -> None:
        self._agent_id = agent_id
        self._workspace_root = Path(workspace_root)
        self._audit_log = audit_log
        self._tenant_id = tenant_id
        # Q5-c: cache operator notes at compilation-cycle start (construction).
        self._operator_notes_cache: dict[str, str] = {}
        self._prime_operator_notes_cache()

    # ------------------------------------------------------------------ cache

    def _deployed_skills_root(self) -> Path:
        return self._workspace_root / ".nexus" / _DEPLOYED_SKILLS_DIRNAME / self._agent_id

    def _prime_operator_notes_cache(self) -> None:
        """Read all operator notes for this agent's skills, once, at cycle start.

        Enumerates skills by their ratings sidecar
        (``deployed-skills/<agent>/<skill_id>/operator-ratings.jsonl``) and
        caches the concatenated non-empty ``note`` fields per ``skill_id``.
        Skills with no notes are simply absent from the cache.
        """
        base = self._deployed_skills_root()
        if not base.is_dir():
            return
        for ratings_file in base.rglob(_RATINGS_FILENAME):
            skill_id = ratings_file.parent.relative_to(base).as_posix()
            notes = self._read_notes(skill_id)
            if notes:
                self._operator_notes_cache[skill_id] = notes

    def _read_notes(self, skill_id: str) -> str:
        """Concatenate this skill's non-empty operator-rating notes."""
        collected: list[str] = []
        for record in read_operator_ratings(
            self._agent_id,
            skill_id,
            audit_log=self._audit_log,
            workspace_root=self._workspace_root,
            tenant_id=self._tenant_id,
        ):
            note = record.get("note")
            if note:
                collected.append(str(note))
        return " ; ".join(collected)

    @property
    def cached_skill_ids(self) -> tuple[str, ...]:
        """Skill ids that had operator notes at cycle start (introspection/tests)."""
        return tuple(sorted(self._operator_notes_cache))

    # ----------------------------------------------------------------- metric

    def __call__(
        self,
        example: Any,
        prediction: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any | None:
        """GEPA ``metric=`` callable.

        ``example`` must carry a ``skill_id`` attribute (the trainset row's
        skill). ``prediction`` and trailing GEPA args are accepted for
        signature compatibility but unused — the metric is the skill's G1
        effectiveness, not the prediction's correctness.

        Returns:
            * ``None`` — skip this example (Q5-a: no score, zero confidence,
              or a graceful G1 read failure). With the Task-5 trainset
              pre-filter this is unreachable in normal operation (defensive).
            * ``ScoreWithFeedback(score, feedback)`` — the modulated scalar
              (Q5-b) plus the reflection string (Q5-c), in DSPy's GEPA
              metric-return type. NOTE: a raw ``tuple`` crashes DSPy's
              evaluator — see ``_score_with_feedback`` (Q5-c drift correction).
        """
        skill_id = getattr(example, "skill_id", None)
        if not skill_id:
            raise ValueError("GEPA metric example must carry a non-empty 'skill_id' attribute")

        # CF #2 graceful-degradation: never let a G1 read failure break compilation.
        try:
            score = get_effectiveness_score(
                skill_id,
                self._agent_id,
                workspace_root=self._workspace_root,
                tenant_id=self._tenant_id,
            )
        except Exception as exc:  # CF #2: emit + skip, never crash the cycle
            self._audit_log.append(
                ACTION_META_HARNESS_SKILL_EFFECTIVENESS_ERROR,
                {
                    "skill_id": skill_id,
                    "agent_id": self._agent_id,
                    "tenant_id": self._tenant_id,
                    "error_type": "effectiveness_read_failed",
                    "exception_message": str(exc),
                    "stack_trace": traceback.format_exc(),
                },
            )
            return None

        # Q5-a: SKIP None or zero-confidence (also guards global_score is None).
        if score is None or score.confidence == 0.0 or score.global_score is None:
            return None

        # Q5-b: MODULATE by score x confidence.
        modulated = score.global_score * score.confidence

        # Q5-c: USE cached operator notes in the reflection string, returned in
        # DSPy's GEPA metric-return type (ScoreWithFeedback) — not a raw tuple.
        return _score_with_feedback(modulated, self._build_reflection(skill_id, score))

    def _build_reflection(self, skill_id: str, score: EffectivenessScore) -> str:
        """Assemble ``reason + axes breakdown + operator notes`` for GEPA reflection."""
        parts: list[str] = []
        if score.reason is not None:
            parts.append(f"reason={score.reason.value}")
        axes = score.axes_breakdown
        if axes is not None:
            parts.append(
                "axes: "
                f"adoption={axes.adoption.score:.2f}@{axes.adoption.confidence:.2f}, "
                f"outcome={axes.outcome.score:.2f}@{axes.outcome.confidence:.2f}, "
                f"feedback={axes.feedback.score:.2f}@{axes.feedback.confidence:.2f}"
            )
        note = self._operator_notes_cache.get(skill_id)
        if note:
            parts.append(f"operator: {note}")
        return " | ".join(parts)


__all__ = ["GEPAMetricAdapter"]
