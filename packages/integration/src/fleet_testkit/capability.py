"""Fleet-test Level 2 capability evaluator (v2 directive §3).

The measurement surface: load a YAML capability test case (§3.2), run the agent's real detection
path against its fixture, then **score** the emitted findings against the case's ground truth and
**evaluate** precision / recall / FP / detection-time against the pass criteria.

The P/R/FP math lives here (shared); the per-agent identity that ties a finding to a ground-truth
violation is the ``match`` callable each agent's ``test_runner.py`` supplies — and that key is
governed by the **match-key registry** (L2 brainstorm Appendix A; operator-gated). A wrong match
key silently inflates precision, so the registry + per-PR review are the guard (no assertion can
catch it).

Honesty rules (swiss-bar #5/#6/#12/#13): a malformed case is a hard error, never a silent skip;
every case must carry INPUT + GROUND TRUTH + PASS CRITERIA; failures name the measured value vs
the threshold and the ground-truth id violated.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_REQUIRED_TOP = (
    "test_case_id",
    "description",
    "agent",
    "category",
    "environment",
    "ground_truth_violations",
    "pass_criteria",
)
_VALID_CATEGORIES = frozenset(
    {
        "clean_baseline",
        "standard_violations",
        "edge_cases",
        "false_positive_traps",
        "cross_domain_inputs",
        "enrichment_context",
        "negative_space",
    }
)


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """One violation the agent is expected to detect (``expected_detect=True``)."""

    id: str
    type: str
    resource: str
    severity: str = "medium"
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NonDetection:
    """A FP trap: something that looks suspicious but must NOT be detected."""

    id: str
    resource: str
    reason: str


@dataclass(frozen=True, slots=True)
class PassCriteria:
    """Thresholds for a case (any may be omitted → not asserted)."""

    precision: float | None = None
    recall: float | None = None
    false_positives_max: int | None = None
    detection_time_max_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class TestCase:
    """A parsed, validated §3.2 capability test case."""

    test_case_id: str
    description: str
    agent: str
    category: str
    fixture_path: str
    ground_truth_violations: tuple[GroundTruth, ...]
    expected_non_detections: tuple[NonDetection, ...]
    pass_criteria: PassCriteria
    realism_notes: str = ""


@dataclass(frozen=True, slots=True)
class CapabilityResult:
    """Scored outcome of one case."""

    test_case_id: str
    true_positives: int
    false_negatives: int
    false_positives: int
    detection_time_seconds: float
    missed: tuple[str, ...]  # ground-truth ids not detected (FN)
    spurious: tuple[str, ...]  # finding labels matching no ground truth (FP)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return 1.0 if denom == 0 else self.true_positives / denom

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return 1.0 if denom == 0 else self.true_positives / denom


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(f"capability test case invalid: {msg}")


def load_test_case(path: Path | str) -> TestCase:
    """Parse + validate a §3.2 capability test-case YAML. Malformed → ``ValueError`` (hard error)."""
    path = Path(path)
    _require(path.is_file(), f"file not found: {path}")
    raw = yaml.safe_load(path.read_text())
    _require(isinstance(raw, dict), f"{path}: top level must be a mapping")
    for key in _REQUIRED_TOP:
        _require(key in raw, f"{path}: missing required key {key!r}")
    _require(
        raw["category"] in _VALID_CATEGORIES,
        f"{path}: category {raw['category']!r} not in {sorted(_VALID_CATEGORIES)}",
    )
    env = raw["environment"]
    _require(
        bool(isinstance(env, dict) and env.get("fixture_path")),
        f"{path}: environment.fixture_path required",
    )

    gts_raw = raw["ground_truth_violations"]
    _require(isinstance(gts_raw, list), f"{path}: ground_truth_violations must be a list")
    # clean_baseline is the one category allowed an empty ground-truth set (it's the 0-detection
    # FP test); every other category must assert at least one violation.
    if raw["category"] != "clean_baseline":
        _require(bool(gts_raw), f"{path}: non-baseline case must list >=1 ground_truth_violation")
    ground_truth = tuple(
        GroundTruth(
            id=_req_field(g, "id", path),
            type=_req_field(g, "type", path),
            resource=_req_field(g, "resource", path),
            severity=str(g.get("severity", "medium")),
            extra={
                k: v
                for k, v in g.items()
                if k not in {"id", "type", "resource", "severity", "expected_detect"}
            },
        )
        for g in gts_raw
    )
    nds = tuple(
        NonDetection(
            id=_req_field(n, "id", path),
            resource=_req_field(n, "resource", path),
            reason=_req_field(n, "reason", path),
        )
        for n in raw.get("expected_non_detections", []) or []
    )
    pc_raw = raw["pass_criteria"]
    _require(isinstance(pc_raw, dict), f"{path}: pass_criteria must be a mapping")
    pass_criteria = PassCriteria(
        precision=_opt_float(pc_raw.get("precision")),
        recall=_opt_float(pc_raw.get("recall")),
        false_positives_max=(
            int(pc_raw["false_positives_max"])
            if pc_raw.get("false_positives_max") is not None
            else None
        ),
        detection_time_max_seconds=_opt_float(pc_raw.get("detection_time_max_seconds")),
    )
    return TestCase(
        test_case_id=str(raw["test_case_id"]),
        description=str(raw["description"]),
        agent=str(raw["agent"]),
        category=str(raw["category"]),
        fixture_path=str(env["fixture_path"]),
        ground_truth_violations=ground_truth,
        expected_non_detections=nds,
        pass_criteria=pass_criteria,
        realism_notes=str(env.get("realism_notes", "")),
    )


def _req_field(d: dict[str, Any], key: str, path: Path) -> str:
    _require(isinstance(d, dict) and d.get(key) not in (None, ""), f"{path}: entry missing {key!r}")
    return str(d[key])


def _opt_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, str):
        # tolerate ">= 0.95" / "0.95" forms from the §3.2 template
        value = value.replace(">=", "").replace(">", "").strip()
    return float(value)


def score(
    detected: Iterable[Any],
    ground_truth: Sequence[GroundTruth],
    non_detections: Sequence[NonDetection] = (),
    *,
    match: Callable[[Any, GroundTruth], bool],
    label: Callable[[Any], str] = repr,
    detection_time_seconds: float = 0.0,
    test_case_id: str = "",
) -> CapabilityResult:
    """Compute TP/FN/FP against ground truth using the per-agent ``match`` (registry-governed).

    - **TP**: a ground-truth violation matched by >=1 emitted finding.
    - **FN**: a ground-truth violation matched by no finding (missed).
    - **FP**: an emitted finding that matches no ground-truth violation. (A finding matching an
      ``expected_non_detection`` is, by construction, a finding that matches no ground truth — so
      it counts as an FP without special-casing; the trap simply means a correct agent emits
      nothing there.)
    """
    findings = list(detected)
    matched_gt: set[str] = set()
    spurious: list[str] = []
    for finding in findings:
        hit = False
        for gt in ground_truth:
            if match(finding, gt):
                matched_gt.add(gt.id)
                hit = True
        if not hit:
            spurious.append(label(finding))
    tp = len(matched_gt)
    fn = [gt.id for gt in ground_truth if gt.id not in matched_gt]
    return CapabilityResult(
        test_case_id=test_case_id,
        true_positives=tp,
        false_negatives=len(fn),
        false_positives=len(spurious),
        detection_time_seconds=detection_time_seconds,
        missed=tuple(fn),
        spurious=tuple(spurious),
    )


def evaluate(result: CapabilityResult, pass_criteria: PassCriteria) -> None:
    """Assert the result meets the criteria; ``AssertionError`` names measured-vs-threshold (#8/#13)."""
    pc = pass_criteria
    if pc.precision is not None:
        assert result.precision >= pc.precision, (
            f"[{result.test_case_id}] precision {result.precision:.3f} < {pc.precision} "
            f"(FP={result.false_positives}, spurious={list(result.spurious)})"
        )
    if pc.recall is not None:
        assert result.recall >= pc.recall, (
            f"[{result.test_case_id}] recall {result.recall:.3f} < {pc.recall} "
            f"(missed ground truth={list(result.missed)})"
        )
    if pc.false_positives_max is not None:
        assert result.false_positives <= pc.false_positives_max, (
            f"[{result.test_case_id}] false_positives {result.false_positives} > "
            f"{pc.false_positives_max} (spurious={list(result.spurious)})"
        )
    if pc.detection_time_max_seconds is not None:
        assert result.detection_time_seconds <= pc.detection_time_max_seconds, (
            f"[{result.test_case_id}] detection_time {result.detection_time_seconds:.3f}s > "
            f"{pc.detection_time_max_seconds}s"
        )


@contextmanager
def detection_timer() -> Any:
    """Time the real detection path: ``with detection_timer() as t: await run(...)`` → ``t.seconds``."""

    class _T:
        seconds: float = 0.0

    t = _T()
    start = time.perf_counter()
    try:
        yield t
    finally:
        t.seconds = time.perf_counter() - start


__all__ = [
    "CapabilityResult",
    "GroundTruth",
    "NonDetection",
    "PassCriteria",
    "TestCase",
    "detection_timer",
    "evaluate",
    "load_test_case",
    "score",
]
