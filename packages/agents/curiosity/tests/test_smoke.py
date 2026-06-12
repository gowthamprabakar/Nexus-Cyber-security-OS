"""Smoke tests — curiosity package imports + substrate gates fire.

Task 1 (Bootstrap). 10 tests:

1. Package version (__version__ wired).
2. ADR-007 v1.1 — charter.llm_adapter reachable (D.12 is an
   LLM-driven agent like D.13; single hypothesizer call per run).
3. ADR-007 v1.2 — charter.nlah_loader reachable.
4. ADR-012 — claims.> substrate reachable (claims_subject +
   CLAIMS_STREAM + JetStreamClient + ForbiddenSubscriptionError).
5. WI-4 — A.1 subscriber-ACL fence still ships in shared.fabric
   (D.12 inherits the guarantee; no new tests needed beyond this
   import-presence probe).
6. D.13 Synthesis reviewer-reuse import (Q6 invariant; Task 7).
7. F.3 / D.6 / D.8 sibling-finding-shape references importable.
8. Anti-pattern guard #1 — no per-agent llm.py (ADR-007 v1.1).
9. Entry-point check #1 — `curiosity` eval-runner registered
   (class lands in Task 12).
10. Entry-point check #2 — `curiosity` CLI script registered
    (main lands in Task 13).
"""

from __future__ import annotations


def test_package_imports() -> None:
    import curiosity

    assert hasattr(curiosity, "__version__")
    assert isinstance(curiosity.__version__, str)
    assert curiosity.__version__ == "0.2.0"


def test_charter_llm_adapter_import_works() -> None:
    """ADR-007 v1.1 — D.12 is an LLM-driven agent (single hypothesizer
    call per run; same hoist pattern as D.13)."""
    from charter.llm_adapter import (  # noqa: F401
        LLMConfig,
        LLMProvider,
        config_from_env,
        make_provider,
    )


def test_charter_nlah_loader_import_works() -> None:
    """ADR-007 v1.2 — D.12 is the **eleventh** agent shipped natively
    against v1.2 (after D.3 / F.6 / D.7 / D.4 / multi-cloud-posture /
    k8s-posture / D.5 / D.8 / D.6 / D.13)."""
    from charter.nlah_loader import (  # noqa: F401
        default_nlah_dir,
        load_system_prompt,
    )


def test_claims_substrate_import_works() -> None:
    """ADR-012 — claims.> subject builder + StreamSpec + ForbiddenSubscription
    are all reachable. D.12 is the first publisher on this substrate.
    """
    from shared.fabric import (  # noqa: F401
        CLAIMS_STREAM,
        ForbiddenSubscriptionError,
        JetStreamClient,
        claims_subject,
    )


def test_a1_subscriber_acl_fence_present() -> None:
    """WI-4 — the ADR-012 fence that prevents A.1 Remediation from
    consuming claims.> still ships in shared.fabric.client. D.12
    inherits the guarantee at the substrate layer; we probe its
    presence here so D.12's smoke suite fails loudly if the fence
    is ever removed upstream.
    """
    from shared.fabric.client import _FORBIDDEN_SUBSCRIPTIONS

    assert "remediation" in _FORBIDDEN_SUBSCRIPTIONS
    assert "claims.>" in _FORBIDDEN_SUBSCRIPTIONS["remediation"]


def test_synthesis_reviewer_import_works() -> None:
    """Q6 invariant — D.12 reuses D.13's classifier-substring guard
    in Task 7. The import must work at bootstrap time so the reviewer
    swap is mechanical, not exploratory."""
    from synthesis.reviewer import _scan_classifier_labels  # noqa: F401


def test_cloud_posture_schema_import_works() -> None:
    """D.12 reads F.3 finding-aggregate state from SemanticStore;
    Task 3's sibling_state_reader needs the F.3 schema shape."""
    from cloud_posture.schemas import OCSF_CLASS_UID  # noqa: F401


def test_compliance_schema_import_works() -> None:
    """D.12 reads D.6 finding-aggregate state."""
    from compliance.schemas import OCSF_CLASS_UID  # noqa: F401


def test_threat_intel_schema_import_works() -> None:
    """D.12 reads D.8 finding-aggregate state for the threat-intel
    context block in the hypothesizer prompt."""
    import threat_intel  # noqa: F401


def test_no_per_agent_llm_module() -> None:
    """ADR-007 v1.1 anti-pattern guard — curiosity must NOT ship a
    local llm.py. Same pressure as D.13; same answer: always go
    through charter.llm_adapter."""
    import importlib.util

    assert importlib.util.find_spec("curiosity.llm") is None, (
        "curiosity must not ship a per-agent llm.py — consume charter.llm_adapter"
    )


def test_eval_runner_entry_point_registered() -> None:
    """Pyproject declares ``curiosity = curiosity.eval_runner:CuriosityEvalRunner``
    under ``nexus_eval_runners``. Class lands in Task 12."""
    from importlib.metadata import entry_points

    runners = entry_points(group="nexus_eval_runners")
    names = {ep.name for ep in runners}
    assert "curiosity" in names, f"curiosity entry-point not registered; got {names}"


def test_cli_script_entry_point_registered() -> None:
    """Pyproject declares ``curiosity = curiosity.cli:main`` under
    ``[project.scripts]``. ``main`` lands in Task 13."""
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    names = {ep.name for ep in scripts}
    assert "curiosity" in names, f"curiosity console script not registered; got {names}"
