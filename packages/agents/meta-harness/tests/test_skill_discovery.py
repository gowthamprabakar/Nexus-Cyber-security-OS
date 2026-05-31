"""Tests — `meta_harness.skill_discovery` (Task 5).

12 tests covering per-agent skill discovery + cross-agent walking:

1.  Empty registry when the agent has no nlah dir.
2.  Empty registry when nlah exists but skills/ subdir is missing.
3.  Empty registry when skills/ exists but no SKILL.md files inside.
4.  Single bundled skill discovered with ``source="bundled"``.
5.  Multiple bundled skills returned in skill_id lex order.
6.  Overlay-only skill discovered with ``source="overlay"``.
7.  Overlay + bundled — overlay masks the shared skill_id; the
    bundled-only skill stays visible.
8.  ``discover_all_agent_skills`` walks every entry-point name.
9.  ``discover_all_agent_skills`` honors ``agent_filter``.
10. ``discover_all_agent_skills`` returns empty registry for v0.1
    agents with no skills dir (backwards-compat regression probe).
11. ``default_shadow_skills_dir`` returns ``<workspace>/.nexus/candidate-skills/<agent_id>``.
12. Malformed frontmatter raises ``SkillLoaderError`` (charter
    exception propagates unchanged).
"""

from __future__ import annotations

from importlib.metadata import EntryPoint
from pathlib import Path

import pytest
from charter.audit import AuditLog
from charter.nlah_loader import SkillLoaderError
from meta_harness import skill_discovery as skill_discovery_module
from meta_harness.skill_discovery import (
    AgentSkillRegistry,
    default_bundled_nlah_dir,
    default_shadow_skills_dir,
    discover_agent_skills,
    discover_all_agent_skills,
)


def _audit(workspace_root: Path) -> AuditLog:
    """Per-test audit sink rooted in the workspace (G2 Task 5 enrichment)."""
    return AuditLog(workspace_root / "audit.jsonl", agent="meta_harness", run_id="test-run")


_MINIMAL_SKILL_MD = """---
name: aws_iam_privesc_via_assumed_role
description: Detect IAM privilege escalation via cross-account role chain.
version: 0.1.0
platforms:
  - nexus
target_agent: investigation
category: iam-privesc
created_by: meta_harness@v0.2.0
provenance:
  - [audit/r_eval.jsonl, deadbeefcafebabe]
eval_gate_status: not_run
deployment_status: candidate
---

When you see cross-account AssumeRole chains, follow the chain head-first.
"""


def _write_bundled_skill(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    content: str = _MINIMAL_SKILL_MD,
) -> Path:
    nlah_dir = default_bundled_nlah_dir(workspace_root, agent_id)
    skill_dir = nlah_dir / "skills" / skill_id
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_path = skill_dir / "SKILL.md"
    skill_path.write_text(content, encoding="utf-8")
    return skill_path


def _write_overlay_skill(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    content: str = _MINIMAL_SKILL_MD,
) -> Path:
    overlay_dir = default_shadow_skills_dir(workspace_root, agent_id) / skill_id
    overlay_dir.mkdir(parents=True, exist_ok=True)
    skill_path = overlay_dir / "SKILL.md"
    skill_path.write_text(content, encoding="utf-8")
    return skill_path


def _fake_entry_point(name: str) -> EntryPoint:
    return EntryPoint(name=name, value="x:y", group="nexus_eval_runners")


# ---------------------------- discover_agent_skills ----------------------------


def test_empty_registry_when_no_nlah_dir(tmp_path: Path) -> None:
    reg = discover_agent_skills(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert isinstance(reg, AgentSkillRegistry)
    assert reg.entries == ()
    assert reg.skills_overlay is None
    assert reg.bundled_entries == ()
    assert reg.overlay_entries == ()
    assert reg.categories == ()


def test_empty_registry_when_nlah_exists_but_no_skills_subdir(tmp_path: Path) -> None:
    nlah_dir = default_bundled_nlah_dir(tmp_path, "investigation")
    nlah_dir.mkdir(parents=True)
    (nlah_dir / "README.md").write_text("# Persona\n", encoding="utf-8")
    reg = discover_agent_skills(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert reg.entries == ()


def test_empty_registry_when_skills_subdir_empty(tmp_path: Path) -> None:
    skills_dir = default_bundled_nlah_dir(tmp_path, "investigation") / "skills"
    skills_dir.mkdir(parents=True)
    reg = discover_agent_skills(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert reg.entries == ()


def test_single_bundled_skill_discovered(tmp_path: Path) -> None:
    _write_bundled_skill(tmp_path, "investigation", "iam-privesc/role-chain")
    reg = discover_agent_skills(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert len(reg.entries) == 1
    entry = reg.entries[0]
    assert entry.skill_id == "iam-privesc/role-chain"
    assert entry.source == "bundled"
    assert entry.target_agent == "investigation"
    assert entry.category == "iam-privesc"
    assert reg.bundled_entries == reg.entries
    assert reg.overlay_entries == ()
    assert reg.categories == ("iam-privesc",)


def test_multiple_bundled_skills_sorted_by_skill_id(tmp_path: Path) -> None:
    _write_bundled_skill(tmp_path, "investigation", "zeta/last")
    _write_bundled_skill(tmp_path, "investigation", "alpha/first")
    reg = discover_agent_skills(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert [e.skill_id for e in reg.entries] == ["alpha/first", "zeta/last"]


def test_overlay_only_skill_discovered(tmp_path: Path) -> None:
    _write_overlay_skill(tmp_path, "investigation", "iam/x")
    reg = discover_agent_skills(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert len(reg.entries) == 1
    assert reg.entries[0].source == "overlay"
    assert reg.overlay_entries == reg.entries
    assert reg.bundled_entries == ()
    assert reg.skills_overlay is not None
    assert reg.skills_overlay.is_dir()


def test_overlay_masks_same_id_bundled_unmasked_still_visible(tmp_path: Path) -> None:
    _write_bundled_skill(
        tmp_path,
        "investigation",
        "iam/shared",
        content=_MINIMAL_SKILL_MD.replace("0.1.0", "0.1.0-bundled"),
    )
    _write_bundled_skill(tmp_path, "investigation", "iam/bundled-only")
    _write_overlay_skill(
        tmp_path,
        "investigation",
        "iam/shared",
        content=_MINIMAL_SKILL_MD.replace("0.1.0", "0.1.0-overlay"),
    )
    reg = discover_agent_skills(
        "investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    by_id = {e.skill_id: e for e in reg.entries}
    assert by_id["iam/shared"].source == "overlay"
    assert by_id["iam/shared"].version == "0.1.0-overlay"
    assert by_id["iam/bundled-only"].source == "bundled"


# ---------------------------- discover_all_agent_skills ----------------------------


def test_discover_all_walks_every_entry_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_bundled_skill(tmp_path, "investigation", "iam/x")
    _write_bundled_skill(tmp_path, "data_security", "pii/y")
    monkeypatch.setattr(
        skill_discovery_module,
        "entry_points",
        lambda *, group: [
            _fake_entry_point("investigation"),
            _fake_entry_point("data_security"),
        ],
    )
    registries = discover_all_agent_skills(workspace_root=tmp_path, audit_log=_audit(tmp_path))
    assert set(registries.keys()) == {"investigation", "data_security"}
    assert len(registries["investigation"].entries) == 1
    assert len(registries["data_security"].entries) == 1
    # Lex-ordered iteration in the entry-point walk
    assert list(registries.keys()) == ["data_security", "investigation"]


def test_discover_all_honors_agent_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_bundled_skill(tmp_path, "investigation", "iam/x")
    _write_bundled_skill(tmp_path, "data_security", "pii/y")
    monkeypatch.setattr(
        skill_discovery_module,
        "entry_points",
        lambda *, group: [
            _fake_entry_point("investigation"),
            _fake_entry_point("data_security"),
        ],
    )
    registries = discover_all_agent_skills(
        workspace_root=tmp_path,
        audit_log=_audit(tmp_path),
        agent_filter={"investigation"},
    )
    assert set(registries.keys()) == {"investigation"}


def test_discover_all_empty_registry_for_v0_1_agents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two agents registered; only ``investigation`` has a skills dir on
    # disk. The other (v0.1 with no skills dir) must produce an empty
    # registry without raising — drift #5 backwards-compat probe.
    _write_bundled_skill(tmp_path, "investigation", "iam/x")
    monkeypatch.setattr(
        skill_discovery_module,
        "entry_points",
        lambda *, group: [
            _fake_entry_point("investigation"),
            _fake_entry_point("vulnerability"),
        ],
    )
    registries = discover_all_agent_skills(workspace_root=tmp_path, audit_log=_audit(tmp_path))
    assert registries["investigation"].entries != ()
    assert registries["vulnerability"].entries == ()


# ---------------------------- helpers + error path ----------------------------


def test_default_shadow_skills_dir_layout(tmp_path: Path) -> None:
    assert (
        default_shadow_skills_dir(tmp_path, "investigation")
        == tmp_path / ".nexus" / "candidate-skills" / "investigation"
    )


def test_malformed_frontmatter_raises_skill_loader_error(tmp_path: Path) -> None:
    skills_dir = default_bundled_nlah_dir(tmp_path, "investigation") / "skills" / "bad/here"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("# No frontmatter at all.\n", encoding="utf-8")
    with pytest.raises(SkillLoaderError, match="missing YAML frontmatter"):
        discover_agent_skills("investigation", workspace_root=tmp_path, audit_log=_audit(tmp_path))


# ---------------------------------------------------------------------------
# G2 Task 5 — effectiveness enrichment
# ---------------------------------------------------------------------------


def _write_effectiveness_sidecar(
    workspace_root: Path,
    agent_id: str,
    skill_id: str,
    *,
    global_score: float | None = 0.85,
    confidence: float = 0.92,
    computed_at: str = "2026-05-26T12:00:00+00:00",
    tenant_id: str = "default",
) -> Path:
    import json

    path = (
        workspace_root / ".nexus" / "deployed-skills" / agent_id / skill_id / "effectiveness.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    # EffectivenessScore requires axes_breakdown when confidence > 0.0;
    # when confidence == 0.0, global_score and axes_breakdown must be None.
    axes_breakdown = (
        {
            "adoption": {"score": 0.9, "confidence": 0.88},
            "outcome": {"score": 0.85, "confidence": 0.90},
            "feedback": {"score": 0.87, "confidence": 0.85},
        }
        if confidence > 0.0
        else None
    )
    reason = "insufficient_data" if confidence == 0.0 else None
    payload: dict[str, object] = {
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "global_score": global_score,
        "confidence": confidence,
        "by_agent": {},
        "by_tenant": {},
        "axes_breakdown": axes_breakdown,
        "reason": reason,
        "computed_at": computed_at,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_enrichment_populates_effectiveness_fields_from_sidecar(tmp_path: Path) -> None:
    """When a sidecar file exists, effectiveness fields are populated."""
    skill_id = "iam-privesc/role-chain"
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, skill_id)
    _write_effectiveness_sidecar(
        tmp_path,
        agent_id,
        skill_id,
        global_score=0.85,
        confidence=0.92,
        computed_at="2026-05-26T12:00:00+00:00",
    )
    reg = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path))
    entry = reg.entries[0]
    assert entry.skill_id == skill_id
    assert entry.effectiveness_score == 0.85
    assert entry.effectiveness_confidence == 0.92
    assert entry.effectiveness_last_updated == "2026-05-26T12:00:00+00:00"


def test_enrichment_defaults_to_none_without_sidecar(tmp_path: Path) -> None:
    """When no sidecar file exists, effectiveness fields remain None."""
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, "iam-privesc/role-chain")
    reg = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path))
    entry = reg.entries[0]
    assert entry.effectiveness_score is None
    assert entry.effectiveness_confidence is None
    assert entry.effectiveness_last_updated is None


def test_enrichment_handles_zero_confidence_score(tmp_path: Path) -> None:
    """confidence=0.0 entries pass through (global_score is None per G1 schema)."""
    skill_id = "iam-privesc/unproven"
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, skill_id)
    _write_effectiveness_sidecar(
        tmp_path,
        agent_id,
        skill_id,
        global_score=None,
        confidence=0.0,
        computed_at="2026-05-26T12:00:00+00:00",
    )
    reg = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path))
    entry = reg.entries[0]
    assert entry.effectiveness_score is None
    assert entry.effectiveness_confidence == 0.0
    assert entry.effectiveness_last_updated == "2026-05-26T12:00:00+00:00"


def test_enrichment_iso_format_preserved(tmp_path: Path) -> None:
    """effectiveness_last_updated preserves the ISO 8601 timestamp verbatim."""
    skill_id = "iam/x"
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, skill_id)
    timestamp = "2026-05-26T14:30:45.123456+00:00"
    _write_effectiveness_sidecar(
        tmp_path,
        agent_id,
        skill_id,
        computed_at=timestamp,
    )
    reg = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path))
    assert reg.entries[0].effectiveness_last_updated == timestamp


def test_enrichment_multiple_skills_mixed_scores(tmp_path: Path) -> None:
    """Some skills have scores, some don't — each gets the right values."""
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, "alpha/scored")
    _write_bundled_skill(tmp_path, agent_id, "beta/unscored")
    _write_effectiveness_sidecar(
        tmp_path, agent_id, "alpha/scored", global_score=0.75, confidence=0.80
    )
    reg = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path))
    by_id = {e.skill_id: e for e in reg.entries}
    assert by_id["alpha/scored"].effectiveness_score == 0.75
    assert by_id["alpha/scored"].effectiveness_confidence == 0.80
    assert by_id["beta/unscored"].effectiveness_score is None
    assert by_id["beta/unscored"].effectiveness_confidence is None


def test_enrichment_corrupt_sidecar_falls_back_to_none(tmp_path: Path) -> None:
    """A corrupt/unparseable sidecar file is treated as no score (graceful)."""
    skill_id = "iam/broken"
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, skill_id)
    sidecar = tmp_path / ".nexus" / "deployed-skills" / agent_id / skill_id / "effectiveness.json"
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text("not valid json {{{", encoding="utf-8")
    reg = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path))
    entry = reg.entries[0]
    # Corrupt file → logged warning → None fallback.
    assert entry.effectiveness_score is None
    assert entry.effectiveness_confidence is None
    assert entry.effectiveness_last_updated is None


def test_enrichment_g1_read_failure_emits_error_and_returns_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CF #2 — an *unexpected* G1 read failure (not a parse error, which
    the store already swallows to None) must emit
    ``meta_harness.skill.effectiveness_error`` to the audit chain AND
    degrade gracefully to None fields. Effectiveness must never break
    skill discovery."""
    skill_id = "iam/explodes"
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, skill_id)

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated filesystem failure reading G1 sidecar")

    monkeypatch.setattr(skill_discovery_module, "get_effectiveness_score", _boom)

    audit_log = _audit(tmp_path)
    reg = discover_agent_skills(agent_id, workspace_root=tmp_path, audit_log=audit_log)
    entry = reg.entries[0]

    # Graceful degradation: all three fields None despite the read failure.
    assert entry.effectiveness_score is None
    assert entry.effectiveness_confidence is None
    assert entry.effectiveness_last_updated is None

    # CF #2: an effectiveness_error was emitted to the audit chain.
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "meta_harness.skill.effectiveness_error" in audit_text
    assert "effectiveness_read_failed" in audit_text
    assert skill_id in audit_text


def test_enrichment_tenant_scoping_preserved(tmp_path: Path) -> None:
    """A score written under one tenant is invisible to another tenant
    (G1 ``get_effectiveness_score`` tenant filter). Default-tenant
    discovery does not pick up a non-default sidecar."""
    skill_id = "iam/tenant-scoped"
    agent_id = "investigation"
    _write_bundled_skill(tmp_path, agent_id, skill_id)
    _write_effectiveness_sidecar(
        tmp_path,
        agent_id,
        skill_id,
        global_score=0.77,
        confidence=0.81,
        tenant_id="acme",
    )

    # Wrong tenant (default) → no score surfaced.
    reg_default = discover_agent_skills(
        agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path)
    )
    assert reg_default.entries[0].effectiveness_score is None
    assert reg_default.entries[0].effectiveness_confidence is None

    # Matching tenant → score surfaced.
    reg_acme = discover_agent_skills(
        agent_id, workspace_root=tmp_path, audit_log=_audit(tmp_path), tenant_id="acme"
    )
    assert reg_acme.entries[0].effectiveness_score == 0.77
    assert reg_acme.entries[0].effectiveness_confidence == 0.81
