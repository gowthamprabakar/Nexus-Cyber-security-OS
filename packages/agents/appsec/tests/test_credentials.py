"""SCM Pattern-A credential resolver tests (D.14 v0.1)."""

from __future__ import annotations

import pytest
from appsec.credentials import ScmCredentialError, ScmCredentialResolver


def test_resolves_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_example")
    resolver = ScmCredentialResolver(scm_type="github")
    assert resolver.resolve_token() == "ghp_example"
    assert resolver.auth_headers() == {"Authorization": "Bearer ghp_example"}


def test_missing_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    resolver = ScmCredentialResolver(scm_type="gitlab")
    with pytest.raises(ScmCredentialError, match="GITLAB_TOKEN is not set"):
        resolver.resolve_token()


def test_unsupported_scm_type_raises() -> None:
    with pytest.raises(ScmCredentialError, match="unsupported scm_type"):
        ScmCredentialResolver(scm_type="perforce")


def test_profile_not_implemented_raises() -> None:
    resolver = ScmCredentialResolver(scm_type="bitbucket", profile="tenant-a")
    with pytest.raises(ScmCredentialError, match="profile-based SCM credential store"):
        resolver.resolve_token()


def test_resolver_stores_no_secret_material() -> None:
    resolver = ScmCredentialResolver(scm_type="github")
    # Pattern-A: only the identifier is state; no token slot exists.
    assert resolver.scm_type == "github"
    assert resolver.profile is None
    assert "_token" not in resolver.__slots__
