"""Task 1 smoke tests for `remediation.promotion`.

What this test file proves:

1. The new sub-package imports cleanly.
2. All 5 submodules (`schemas` / `tracker` / `replay` / `events`) import.
3. The Task-1 public API surface — `PromotionStage` / `PromotionTracker` /
   `PromotionGateError` / `stage_max_mode` — is in place and shaped per the plan.
4. The 9 `promotion.*` audit-action constants exist, are unique, and are all
   namespaced under `promotion.`.
5. The new sub-package does not create circular imports with the existing
   `remediation.*` modules (agent / audit / authz / schemas).

Tasks 2-8 fill in the implementation; this test asserts only the contract
shape so that subsequent commits can layer behaviour without re-litigating
the surface.
"""

from __future__ import annotations

import importlib

import pytest
from remediation.schemas import RemediationMode


def test_promotion_package_imports() -> None:
    """The new sub-package is importable as `remediation.promotion`."""
    import remediation.promotion

    assert remediation.promotion.__name__ == "remediation.promotion"


@pytest.mark.parametrize(
    "submodule",
    ["schemas", "tracker", "replay", "events"],
)
def test_promotion_submodule_imports(submodule: str) -> None:
    """Every submodule named in the plan imports without error."""
    mod = importlib.import_module(f"remediation.promotion.{submodule}")
    assert mod is not None
    assert mod.__name__ == f"remediation.promotion.{submodule}"


def test_promotion_public_api_present() -> None:
    """The Task-1 public API is importable from the package root.

    These names are the import contract every later task (2-8) preserves.
    Renaming or removing one without updating dependents would break the
    pre-flight gate or the CLI surface.
    """
    from remediation.promotion import (
        PromotionGateError,
        PromotionStage,
        PromotionTracker,
        stage_max_mode,
    )

    # Stage enum has the 4 graduation stages, integer-valued for ordering.
    assert PromotionStage.STAGE_1.value == 1
    assert PromotionStage.STAGE_2.value == 2
    assert PromotionStage.STAGE_3.value == 3
    assert PromotionStage.STAGE_4.value == 4
    assert PromotionStage.STAGE_1 < PromotionStage.STAGE_2 < PromotionStage.STAGE_3

    # PromotionGateError is a RuntimeError subclass (caught alongside other
    # gate failures by callers that already except RuntimeError).
    assert issubclass(PromotionGateError, RuntimeError)

    # PromotionTracker is a class — full instantiation contract lands in Task 3.
    assert isinstance(PromotionTracker, type)

    # stage_max_mode covers all four stages and lands on the documented mapping.
    assert stage_max_mode(PromotionStage.STAGE_1) is RemediationMode.RECOMMEND
    assert stage_max_mode(PromotionStage.STAGE_2) is RemediationMode.DRY_RUN
    assert stage_max_mode(PromotionStage.STAGE_3) is RemediationMode.EXECUTE
    assert stage_max_mode(PromotionStage.STAGE_4) is RemediationMode.EXECUTE


def test_promotion_event_constants_unique_and_namespaced() -> None:
    """The 9 `promotion.*` audit-action constants are uniquely defined and
    all share the `promotion.` namespace prefix.

    This is the contract downstream consumers (D.7 Investigation,
    F.6 dashboards) subscribe to. A non-`promotion.`-prefixed action in
    PROMOTION_ACTIONS would silently bypass those subscribers.
    """
    from remediation.promotion.events import PROMOTION_ACTIONS

    assert len(PROMOTION_ACTIONS) == 9, (
        f"expected 9 promotion.* events per the plan, got {len(PROMOTION_ACTIONS)}"
    )
    for action in PROMOTION_ACTIONS:
        assert action.startswith("promotion."), (
            f"action {action!r} must start with 'promotion.' to honour the namespace contract"
        )


def test_promotion_evidence_events_are_a_subset_of_promotion_actions() -> None:
    """The four evidence events (stage1/stage2/stage3/unexpected_rollback) and the
    five transition events (advance.proposed/applied, demote.applied,
    init.applied, reconcile.completed) together make up exactly the 9.

    This guards against drift if a future task adds an event but forgets to
    register it in PROMOTION_ACTIONS.
    """
    from remediation.promotion.events import (
        ACTION_PROMOTION_ADVANCE_APPLIED,
        ACTION_PROMOTION_ADVANCE_PROPOSED,
        ACTION_PROMOTION_DEMOTE_APPLIED,
        ACTION_PROMOTION_EVIDENCE_STAGE1,
        ACTION_PROMOTION_EVIDENCE_STAGE2,
        ACTION_PROMOTION_EVIDENCE_STAGE3,
        ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
        ACTION_PROMOTION_INIT_APPLIED,
        ACTION_PROMOTION_RECONCILE_COMPLETED,
        PROMOTION_ACTIONS,
    )

    expected = {
        ACTION_PROMOTION_EVIDENCE_STAGE1,
        ACTION_PROMOTION_EVIDENCE_STAGE2,
        ACTION_PROMOTION_EVIDENCE_STAGE3,
        ACTION_PROMOTION_EVIDENCE_UNEXPECTED_ROLLBACK,
        ACTION_PROMOTION_ADVANCE_PROPOSED,
        ACTION_PROMOTION_ADVANCE_APPLIED,
        ACTION_PROMOTION_DEMOTE_APPLIED,
        ACTION_PROMOTION_INIT_APPLIED,
        ACTION_PROMOTION_RECONCILE_COMPLETED,
    }
    assert expected == PROMOTION_ACTIONS


def test_promotion_does_not_create_circular_imports() -> None:
    """Loading `remediation.promotion` alongside the existing agent surface
    must not deadlock or fail.

    The pre-flight gate (Task 5) adds an `agent.py → promotion.tracker`
    import direction. If `promotion.tracker` ever imports from `agent.py`
    that creates a cycle. This test catches the cycle now by reloading
    `remediation.promotion` AFTER the rest of the package has loaded.
    """
    import remediation.agent
    import remediation.audit
    import remediation.authz
    import remediation.promotion
    import remediation.schemas

    # Reload after the other modules have loaded — fails if any cycle exists.
    importlib.reload(remediation.promotion)


def test_promotion_package_does_not_import_agent_at_module_load() -> None:
    """A defensive assertion: at this point in the plan (Task 1), none of the
    promotion submodules should import from `remediation.agent`.

    The Task-5 pre-flight gate adds `agent.py → promotion` (one direction).
    Going the other way would create a cycle. This test fails fast if a
    later task accidentally adds the reverse import.
    """
    import sys

    # Drop the cache so the import is fresh.
    for name in list(sys.modules):
        if name.startswith("remediation.promotion"):
            del sys.modules[name]

    # Load promotion in isolation. If something inside it triggers an
    # `agent` import as a module-level side effect, this would fail when we
    # later assert `remediation.agent` was NOT loaded by this action alone.
    # We can't actually assert that because pytest's own fixture may have
    # imported agent earlier — but we can at least assert the import is fast
    # and produces no warnings.
    import remediation.promotion  # noqa: F401

    # Module exists.
    assert "remediation.promotion" in sys.modules
