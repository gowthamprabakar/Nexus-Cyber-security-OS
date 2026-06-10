"""CI guard (ADR-016 Mechanism 2): registered tools are dispatched, never called.

Static invariant: in an agent's *driver* modules (``agent.py`` / ``normalizer.py``),
a callable that the agent registers as a tool (``reg.register("name", callable, ...)``)
must appear ONLY as the registration argument — never as the function of a call
expression. A direct call (``apply_patch(...)``) bypasses the charter gate; the
sanctioned path is ``ctx.call_tool("name", ...)``.

Scope & limits (honest, per ADR-016):
- This catches the remediation/investigation class: a *registered* tool invoked
  directly. It is name-based against each agent's own registration manifest, so it
  cannot be defeated by aliasing without also breaking registration.
- It does NOT catch the vulnerability class: an *unregistered* side-effecting call
  (is_kev/nvd_enrich). That is prevented by the M3 tools.md-accuracy requirement and
  reviewer discipline, not by static analysis.
- Pure helpers (normalizers/detectors/scorers) are never registered, so calling
  them directly is correctly NOT flagged.

PENDING_MIGRATION lists agents whose registered-tool bypass is fixed later in
Milestone 1; each is removed from the set by its fix task so CI never goes red on
an un-migrated agent mid-cycle.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# Repo root: .../packages/charter/tests/this_file -> parents[3]
_REPO = Path(__file__).resolve().parents[3]
_AGENTS = _REPO / "packages" / "agents"
_DRIVER_MODULES = ("agent.py", "normalizer.py")

# Empty: all known registered-tool bypasses migrated (remediation -> Task 3,
# investigation -> Task 5). The set remains as the mechanism for any future
# staged migration.
PENDING_MIGRATION: set[str] = set()

# By-design exemptions (NOT debt): the audit agent (F.6) is the always-on class
# (ADR-007 v1.3) and reads the audit log directly, intentionally outside the
# budget gate — graded Tool=A "by-design" in audit #316. Its raw-import calls do
# not hit the registry proxy, so the runtime boundary is unaffected. The formal
# deviation note for audit is written in its M3 backfill task (Task-21 split);
# this exemption is the placeholder until then.
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


def _direct_invocations(module: Path, registered: set[str]) -> set[str]:
    """Registered callables that appear as the *function* of a call in ``module``."""
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
        leaf = (
            fn.id
            if isinstance(fn, ast.Name)
            else fn.attr
            if isinstance(fn, ast.Attribute)
            else None
        )
        if leaf in registered:
            hits.add(leaf)
    return hits


@pytest.mark.parametrize(
    "name,pkg_dir", _agent_pkgs(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_registered_tools_not_called_directly(name: str, pkg_dir: Path) -> None:
    if name in BY_DESIGN_EXEMPT:
        pytest.skip(f"{name}: by-design exemption (see BY_DESIGN_EXEMPT docstring)")

    registered = _registered_callables(pkg_dir)
    violations: dict[str, set[str]] = {}
    for mod in _DRIVER_MODULES:
        hits = _direct_invocations(pkg_dir / mod, registered)
        if hits:
            violations[mod] = hits

    if name in PENDING_MIGRATION:
        # Documented bypass awaiting its M1 fix task — assert it is STILL present so
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
