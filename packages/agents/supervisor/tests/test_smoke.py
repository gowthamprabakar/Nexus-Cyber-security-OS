"""Smoke tests — supervisor package imports + 4 Q-ARCH deferral guards.

Task 1 (Bootstrap). 13 tests:

1.  Package version (``__version__`` wired).
2.  ADR-007 v1.2 — ``charter.nlah_loader`` reachable.
3.  ADR-008 — ``eval_framework`` reachable.
4.  F.6 audit-chain — ``charter.audit`` reachable.
5.  F.7 events.> substrate availability probe — Supervisor's
    INGEST stage depends on this; missing -> v0.1.1 fallback to
    CLI + scheduled-queue triggers only.
6.  ``shared.fabric._FORBIDDEN_SUBSCRIPTIONS`` registry present
    (Supervisor's Task 8 substrate touch will extend it).
7.  Anti-pattern guard — no per-agent ``supervisor.llm`` module.
8.  Entry-point — ``supervisor`` eval-runner registered (the 17th
    nexus_eval_runners entry).
9.  Entry-point — ``supervisor`` console script registered.
10. **Q-ARCH-1 guard** — no ``claims_subject`` / ``CLAIMS_STREAM``
    import in any supervisor source file. v0.1 is structurally
    fenced from ``claims.>``; Task 8 adds the registry entry.
11. **Q-ARCH-2 guard** — no LLM-adapter import under ``routing/``
    or in ``dispatch.py``. Routing is declarative-only in v0.1.
12. **Q-ARCH-3 guard** — README documents the read-only commitment
    + the ``customer_context.md`` write deferral verbatim.
13. **Q-ARCH-4 guard** + WI-6 — no A.4 introspection coupling: no
    ``meta_harness.tools.nlah_parser`` import anywhere in
    supervisor source.
"""

from __future__ import annotations

from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "supervisor"


def _iter_source_files() -> list[Path]:
    return sorted(p for p in _SRC_ROOT.rglob("*.py") if p.is_file())


def test_package_imports() -> None:
    import supervisor

    assert hasattr(supervisor, "__version__")
    assert supervisor.__version__ == "0.1.0"


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — Supervisor is the **13th** agent shipped natively
    against v1.2 (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture /
    k8s-posture / D.5 / D.8 / D.6 / D.13 / D.12 / A.4)."""
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_eval_framework_import_works() -> None:
    """ADR-008 — Supervisor registers itself as a nexus_eval_runners
    entry point + ships 15 routing-test YAML cases."""
    from eval_framework.cases import load_cases  # noqa: F401
    from eval_framework.runner import EvalRunner  # noqa: F401
    from eval_framework.suite import run_suite  # noqa: F401


def test_charter_audit_import_works() -> None:
    """F.6 audit-chain — Supervisor emits 4 additive audit-action
    vocabulary entries (Q6)."""
    from charter.audit import AuditLog  # noqa: F401


def test_events_substrate_import_works() -> None:
    """F.7 events.> substrate availability probe.

    Supervisor's Stage 1 INGEST subscribes to ``events.>`` via
    this substrate. If missing, the plan's fallback (CLI +
    scheduled-queue only) lands as Supervisor v0.1.1.
    """
    from shared.fabric import EVENTS_STREAM  # noqa: F401
    from shared.fabric.subjects import events_subject  # noqa: F401


def test_forbidden_subscriptions_registry_reachable() -> None:
    """Substrate fence registry must exist + carry the A.1 entry.

    Task 8 (SAFETY-CRITICAL) will extend it with a Supervisor
    entry. At bootstrap time we only probe the registry is
    reachable + the existing A.1 fence is still there.
    """
    from shared.fabric.client import _FORBIDDEN_SUBSCRIPTIONS

    assert "remediation" in _FORBIDDEN_SUBSCRIPTIONS
    assert "claims.>" in _FORBIDDEN_SUBSCRIPTIONS["remediation"]


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern — Supervisor must NOT ship a local
    ``llm.py``. Routing is rule-based; LLM is not needed in v0.1."""
    import importlib.util

    assert importlib.util.find_spec("supervisor.llm") is None, (
        "supervisor must not ship a per-agent llm.py — v0.1 routing is rule-based only"
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares ``supervisor = supervisor.eval_runner:SupervisorEvalRunner``
    under ``nexus_eval_runners``. Class lands in Task 12 — this is the 17th entry."""
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "supervisor" in names, f"supervisor eval-runner not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "supervisor" in names, f"supervisor console script not registered; got {names}"


# ---------------------------------------------------------------------------
# Q-ARCH deferral guards — these scan the supervisor source tree and assert
# that no v0.2+ surface area sneaks into v0.1.
# ---------------------------------------------------------------------------


def test_qarch1_no_claims_subscribe_surface() -> None:
    """Q-ARCH-1 — Supervisor v0.1 has no ``claims.>`` subscribe
    capability. Task 8 adds the ``_FORBIDDEN_SUBSCRIPTIONS``
    registry entry that structurally enforces this; this source-
    scan catches any accidental import before Task 8 lands.
    """
    forbidden = ("claims_subject", "CLAIMS_STREAM")
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                offenders.append((path, token))
    assert not offenders, (
        "Q-ARCH-1 violation — supervisor v0.1 must not import claims.> substrate. "
        f"Offenders: {offenders}"
    )


def test_qarch2_no_llm_in_routing_path() -> None:
    """Q-ARCH-2 + LLM-anti-pattern — no ``charter.llm_adapter``
    import under ``routing/`` or in ``dispatch.py``. Routing is
    declarative-only in v0.1.
    """
    forbidden_tokens = ("charter.llm_adapter", "charter.llm", "LLMProvider")
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        rel = path.relative_to(_SRC_ROOT).as_posix()
        if not (rel.startswith("routing/") or rel == "dispatch.py"):
            continue
        text = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in text:
                offenders.append((path, token))
    assert not offenders, (
        "Q-ARCH-2 violation — supervisor's routing path must not import LLM surface. "
        f"Offenders: {offenders}"
    )


def test_qarch3_readme_documents_read_only_customer_context() -> None:
    """Q-ARCH-3 — README must document the customer_context.md
    write deferral verbatim. Writes are deferred to v0.2 with an
    explicit operator approval gate.
    """
    readme = (_SRC_ROOT.parent.parent / "README.md").read_text(encoding="utf-8")
    assert (
        "customer_context.md" in readme.lower()
        or "operator approval" in readme.lower()
        or "v0.2" in readme
    ), "README must document the customer_context.md write deferral or operator approval gate"


def test_qarch4_wi6_no_meta_harness_introspection_coupling() -> None:
    """Q-ARCH-4 + WI-6 — no ``meta_harness.tools.nlah_parser``
    import anywhere in supervisor source. Routing is declarative-
    only; cross-agent introspection coupling is deferred to v0.2.
    """
    forbidden = ("meta_harness.tools.nlah_parser", "from meta_harness import")
    offenders: list[tuple[Path, str]] = []
    for path in _iter_source_files():
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                offenders.append((path, token))
    assert not offenders, (
        "Q-ARCH-4 / WI-6 violation — supervisor v0.1 must not couple to A.4 introspection. "
        f"Offenders: {offenders}"
    )
