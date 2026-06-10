"""D.8 v0.2 Task 11 — customer tech-stack profile loading tests."""

from __future__ import annotations

from pathlib import Path

from threat_intel.customer.tech_stack_profile import (
    TechStackProfile,
    cve_relevant_to_stack,
    load_tech_stack_profile,
    load_tech_stack_profile_from_path,
)

_CONTEXT = """---
industry: technology
tech_stack:
  cloud: aws, gcp
  languages:
    - python
    - go
  frameworks: django
  containers: docker, kubernetes
---

# Customer
"""


def test_loads_all_categories() -> None:
    prof = load_tech_stack_profile(_CONTEXT)
    assert prof == TechStackProfile(
        cloud_providers=("aws", "gcp"),
        languages=("python", "go"),
        frameworks=("django",),
        containers=("docker", "kubernetes"),
    )


def test_keywords_are_flat_and_lowercased() -> None:
    prof = load_tech_stack_profile(_CONTEXT)
    assert prof is not None
    assert prof.keywords == {"aws", "gcp", "python", "go", "django", "docker", "kubernetes"}


def test_no_frontmatter_returns_none() -> None:
    assert load_tech_stack_profile("# Customer\nno frontmatter\n") is None


def test_frontmatter_without_tech_stack_returns_none() -> None:
    assert load_tech_stack_profile("---\nindustry: technology\n---\n") is None


def test_partial_categories() -> None:
    prof = load_tech_stack_profile("---\ntech_stack:\n  cloud: azure\n---\n")
    assert prof is not None
    assert prof.cloud_providers == ("azure",) and prof.languages == ()


def test_cve_relevant_when_keyword_present() -> None:
    prof = load_tech_stack_profile(_CONTEXT)
    assert prof is not None
    assert cve_relevant_to_stack(prof, "A Django template injection in the web app") is True


def test_cve_not_relevant_when_no_keyword() -> None:
    prof = load_tech_stack_profile(_CONTEXT)
    assert prof is not None
    assert cve_relevant_to_stack(prof, "A Windows SMB remote code execution") is False


def test_load_from_path(tmp_path: Path) -> None:
    p = tmp_path / "customer_context.md"
    p.write_text(_CONTEXT, encoding="utf-8")
    prof = load_tech_stack_profile_from_path(p)
    assert prof is not None and "kubernetes" in prof.keywords


def test_load_from_missing_path_returns_none(tmp_path: Path) -> None:
    assert load_tech_stack_profile_from_path(tmp_path / "nope.md") is None
