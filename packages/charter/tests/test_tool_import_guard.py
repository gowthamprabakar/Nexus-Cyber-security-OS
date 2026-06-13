"""CI guard (ADR-016 Mechanism 2): registered tools are dispatched, never called.

Static invariant: a callable that an agent registers as a tool
(``reg.register("name", callable, ...)``) must appear ONLY as the registration
argument — never as the *function* of a call expression anywhere in the agent's
``src/<agent>/`` tree. A direct call (``apply_patch(...)``) bypasses the charter
gate; the sanctioned path is ``ctx.call_tool("name", ...)``.

**Scope (widened by the P1 amendment, 2026-06-13, after the v0.2 Quality Audit
PR #622).** The v0.2 audit found a registered-tool bypass on the remediation
**rollback** path (``validator.py``) that the original two-module scope
(``agent.py`` / ``normalizer.py``) could not see. The scan is now **fleet-wide**:
every ``.py`` under each agent's package directory is inspected. During the
5-7 week Phase C wiring sprint, ~36 invariants get wired into ``run()`` loops
across 17 agents — this widened net is the automated backstop against
re-introducing the bypass class anywhere.

**Match rule (avoids SDK name collisions).** In the *driver* modules
(``agent.py`` / ``normalizer.py``) both bare-name (``apply_patch(...)``) and
attribute (``mod.apply_patch(...)``) calls of a registered callable are flagged,
preserving the original behaviour. In every *other* module only **bare-name**
calls are flagged. This is deliberate: tool implementation modules legitimately
call SDK methods that share a name with a registered function — e.g.
cloud-posture registers a function ``list_buckets`` while ``aws_s3.py`` calls the
boto3 ``client.list_buckets()`` method. Matching attribute calls fleet-wide would
false-positive on every such SDK method. The real bypass class (import the
registered tool, call it bare — as ``validator.py`` did) is a bare-name call, so
bare-name matching catches it without the SDK noise.

Limits (honest, per ADR-016):
- Still does NOT catch the *unregistered* side-effecting call class
  (is_kev/nvd_enrich-style). That is the M3 tools.md-accuracy + reviewer
  discipline's job, not static analysis.
- An attribute-style bypass of a registered tool in a non-driver module
  (``some_mod.apply_patch(...)``) is not flagged outside the driver modules — the
  trade-off accepted to keep SDK methods quiet. The runtime proxy
  (``DirectInvocationBlocked``) remains the primary, type-aware guard.

PENDING_MIGRATION lists agents with a *known* registered-tool bypass awaiting a
later fix task; the test asserts the bypass is STILL present for each (so the
entry is removed the moment the fix lands — fail-on-unexpected-pass).
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

# Repo root: .../packages/charter/tests/this_file -> parents[3]
_REPO = Path(__file__).resolve().parents[3]
_AGENTS = _REPO / "packages" / "agents"

# Driver modules get the stricter bare-name + attribute match (no SDK calls live
# here). Every other module is scanned bare-name-only (see module docstring).
_DRIVER_MODULES = ("agent.py", "normalizer.py")

# Known registered-tool bypasses awaiting a dedicated fix task (debt, NOT
# by-design). Surfaced by the P1 widened scan (v0.2 audit PR #622).
#
# Phase C SS4 (2026-06-13) emptied this set: the vulnerability bypass —
# tools/registry_scan.py calling the registered `trivy_image_scan` directly —
# was fixed by threading the active Charter through the registry-scan chain
# (registry_scan -> {ecr,acr,gcr}_scan -> registry_pipeline) so Trivy now
# dispatches via `ctx.call_tool` (ADR-016). No bypasses remain.
PENDING_MIGRATION: set[str] = set()

# By-design exemptions (NOT debt): the audit agent (F.6) is the always-on class
# (ADR-007 v1.3) and reads the audit log directly, intentionally outside the
# budget gate — graded Tool=A "by-design" in audit #316. Its raw-import calls do
# not hit the registry proxy, so the runtime boundary is unaffected.
BY_DESIGN_EXEMPT = {"audit"}


def _agent_pkgs() -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    if not _AGENTS.exists():
        return out
    for d in sorted(_AGENTS.iterdir()):
        src = d / "src"
        if not src.is_dir():
            continue
        pkg_dirs = [p for p in src.iterdir() if p.is_dir() and (p / "agent.py").exists()]
        if pkg_dirs:
            out.append((d.name, pkg_dirs[0]))
    return out


def _registered_callables(pkg_dir: Path) -> set[str]:
    """Leaf identifiers passed as the 2nd arg of any ``*.register(name, callable, ...)``."""
    names: set[str] = set()
    agent_py = pkg_dir / "agent.py"
    if not agent_py.exists():
        return names
    tree = ast.parse(agent_py.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "register"
            and len(node.args) >= 2
        ):
            callable_arg = node.args[1]
            if isinstance(callable_arg, ast.Name):
                names.add(callable_arg.id)
            elif isinstance(callable_arg, ast.Attribute):
                names.add(callable_arg.attr)
    return names


def _direct_invocations(module: Path, registered: set[str], *, match_attr: bool) -> set[str]:
    """Registered callables that appear as the *function* of a call in ``module``.

    ``match_attr`` widens matching to attribute calls (``mod.tool(...)``) — used only
    for driver modules. Non-driver modules match bare-name calls only, so SDK methods
    that share a name with a registered function (e.g. boto3 ``client.list_buckets()``)
    are not false-positives.
    """
    if not registered or not module.exists():
        return set()
    tree = ast.parse(module.read_text(encoding="utf-8"))
    hits: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Skip the registration calls themselves (callable passed as arg, not called).
        if isinstance(node.func, ast.Attribute) and node.func.attr == "register":
            continue
        fn = node.func
        if isinstance(fn, ast.Name):
            if fn.id in registered:
                hits.add(fn.id)
        elif isinstance(fn, ast.Attribute) and match_attr and fn.attr in registered:
            hits.add(fn.attr)
    return hits


def _scan_pkg(pkg_dir: Path, registered: set[str]) -> dict[str, set[str]]:
    """Fleet-wide scan: every .py under the agent package, keyed by relative path."""
    violations: dict[str, set[str]] = {}
    for module in sorted(pkg_dir.rglob("*.py")):
        rel = module.relative_to(pkg_dir)
        hits = _direct_invocations(module, registered, match_attr=(rel.name in _DRIVER_MODULES))
        if hits:
            violations[str(rel)] = hits
    return violations


@pytest.mark.parametrize(
    "name,pkg_dir", _agent_pkgs(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_registered_tools_not_called_directly(name: str, pkg_dir: Path) -> None:
    if name in BY_DESIGN_EXEMPT:
        pytest.skip(f"{name}: by-design exemption (see BY_DESIGN_EXEMPT docstring)")

    registered = _registered_callables(pkg_dir)
    violations = _scan_pkg(pkg_dir, registered)

    if name in PENDING_MIGRATION:
        # Documented bypass awaiting its fix task — assert it is STILL present so
        # this exemption is removed the moment the fix lands (fail-on-unexpected-pass).
        assert violations, (
            f"{name} is in PENDING_MIGRATION but no registered-tool direct call was "
            f"found — remove it from PENDING_MIGRATION."
        )
        return

    assert not violations, (
        f"{name}: registered tool(s) invoked directly instead of via ctx.call_tool — "
        f"{violations}. Route through the charter (ADR-016) or, if pure, do not register it."
    )


def test_guard_catches_validator_style_bypass(tmp_path: Path) -> None:
    """Regression: the widened guard MUST catch a registered tool called directly in a
    non-driver module — the validator.py bypass class the narrow scope missed (v0.2 audit
    PR #622)."""
    pkg = tmp_path / "fake_agent" / "src" / "fake_agent"
    pkg.mkdir(parents=True)
    (pkg / "agent.py").write_text(
        textwrap.dedent(
            """
            from fake_agent.tools.kubectl import apply_patch

            def build_registry(reg):
                reg.register("apply_patch", apply_patch, version="0.1.0", cloud_calls=1)
            """
        ),
        encoding="utf-8",
    )
    (pkg / "validator.py").write_text(
        textwrap.dedent(
            """
            from fake_agent.tools.kubectl import apply_patch

            async def rollback(artifact):
                return await apply_patch(artifact, dry_run=False)
            """
        ),
        encoding="utf-8",
    )
    registered = _registered_callables(pkg)
    assert registered == {"apply_patch"}
    violations = _scan_pkg(pkg, registered)
    assert "validator.py" in violations
    assert "apply_patch" in violations["validator.py"]


def test_guard_clean_module_has_no_false_positive(tmp_path: Path) -> None:
    """A non-driver module that calls an SDK method sharing a registered function's name
    (e.g. boto3 client.list_buckets()) must NOT be flagged — bare-name-only matching."""
    pkg = tmp_path / "fake_agent2" / "src" / "fake_agent2"
    pkg.mkdir(parents=True)
    (pkg / "agent.py").write_text(
        textwrap.dedent(
            """
            from fake_agent2.tools.aws import list_buckets

            def build_registry(reg):
                reg.register("aws_s3_list_buckets", list_buckets, version="1.0", cloud_calls=1)
            """
        ),
        encoding="utf-8",
    )
    (pkg / "tools_aws.py").write_text(
        textwrap.dedent(
            """
            import boto3

            def _impl():
                client = boto3.client("s3")
                return client.list_buckets()  # SDK method, NOT the registered function
            """
        ),
        encoding="utf-8",
    )
    registered = _registered_callables(pkg)
    assert registered == {"list_buckets"}
    violations = _scan_pkg(pkg, registered)
    assert violations == {}
