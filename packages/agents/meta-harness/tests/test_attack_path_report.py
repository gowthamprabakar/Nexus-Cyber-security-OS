"""The customer-facing render of ranked attack paths — text report + JSON + CLI wiring."""

from click.testing import CliRunner
from meta_harness.attack_path_remediation import REMEDIATION, advice_for
from meta_harness.attack_path_report import (
    path_label,
    path_to_dict,
    render_report,
    severity_band,
)
from meta_harness.attack_paths import _SEVERITY, AttackPath
from meta_harness.cli import main


def _path(path_type, severity, title="t", entities=("a",), evidence=("e",), count=1):
    return AttackPath(path_type, severity, title, entities, evidence, count)


def test_severity_bands():
    assert severity_band(95) == "CRITICAL"
    assert severity_band(90) == "CRITICAL"
    assert severity_band(80) == "HIGH"
    assert severity_band(60) == "MEDIUM"
    assert severity_band(40) == "LOW"


def test_path_label_known_and_fallback():
    assert path_label("crown_jewel") == "Crown jewel"
    assert path_label("some_new_type") == "Some new type"  # fallback


def test_to_dict_shape():
    d = path_to_dict(_path("crown_jewel", 95, count=9, evidence=("CVE-1", "CVE-2")))
    assert d["path_type"] == "crown_jewel"
    assert d["label"] == "Crown jewel"
    assert d["severity_band"] == "CRITICAL"
    assert d["count"] == 9
    assert d["evidence"] == ["CVE-1", "CVE-2"]


def test_render_report_ranks_and_summarizes():
    paths = [
        _path("crown_jewel", 95, "exposed+vuln+role", entities=("w", "i", "r", "b"), count=9),
        _path("public_secret", 90, "public AWS key", entities=("k", "d")),
    ]
    out = render_report(paths, tenant_id="acme")
    assert "Top attack paths for tenant acme (2 found):" in out
    assert "1. [CRITICAL 95] Crown jewel" in out
    assert "2. [CRITICAL 90] Public secret" in out
    assert "9 findings · 4 resources" in out  # plural
    assert "1 finding · 2 resources" in out  # singular finding


def test_render_report_truncates_with_total():
    paths = [_path("public_secret", 90 - i, f"t{i}") for i in range(15)]
    out = render_report(paths, tenant_id="t", limit=10)
    assert "(15 found, showing 10):" in out
    assert out.count("[") == 10  # only 10 rows rendered


def test_render_report_empty():
    assert render_report([], tenant_id="t") == "No attack paths found for tenant t."


def test_every_archetype_has_remediation_advice():
    # No path the ranker can emit may render without a fix.
    assert set(REMEDIATION) == set(_SEVERITY)


def test_only_privileged_vulnerable_is_auto_fixable():
    # Honest: A.1 only does K8s patches today, so exactly one archetype is auto-fixable.
    auto = {pt for pt, a in REMEDIATION.items() if a.auto_fixable}
    assert auto == {"privileged_vulnerable"}
    assert advice_for("privileged_vulnerable").auto_via.startswith("remediation_k8s_patch_")


def test_to_dict_includes_remediation():
    d = path_to_dict(_path("public_secret", 90))
    assert d["fix"].startswith("Rotate the exposed credential")
    assert d["auto_fixable"] is False
    assert d["auto_via"] == ""
    d2 = path_to_dict(_path("privileged_vulnerable", 78))
    assert d2["auto_fixable"] is True
    assert d2["auto_via"] == "remediation_k8s_patch_disable_privileged_container"


def test_render_includes_fix_and_auto_fix_lines():
    out = render_report(
        [_path("public_secret", 90), _path("privileged_vulnerable", 78)], tenant_id="t"
    )
    assert "Fix: Rotate the exposed credential" in out
    assert "Auto-fix: no (manual)" in out
    assert "Auto-fix: yes (remediation_k8s_patch_disable_privileged_container)" in out


def test_cli_attack_paths_is_wired():
    # The command is registered with the expected options (live store path is operator-run).
    result = CliRunner().invoke(main, ["attack-paths", "--help"])
    assert result.exit_code == 0
    assert "--customer-id" in result.output
    assert "--dsn" in result.output
    assert "--json" in result.output
