"""Clone-for-scan tests (D.14 B-1 PR6) — injected runner, no real git/network."""

from __future__ import annotations

from pathlib import Path

import pytest
from appsec.schemas import RepoRef
from appsec.tools import repo_clone
from appsec.tools.repo_clone import _authed_url, clone_repository

pytestmark = pytest.mark.asyncio

_REPO = RepoRef(
    host="github",
    owner="acme",
    name="api",
    clone_url="https://github.com/acme/api.git",
)


def test_authed_url_injects_token_for_https() -> None:
    url = _authed_url("https://github.com/acme/api.git", "TOK")  # test token
    assert url == "https://x-access-token:TOK@github.com/acme/api.git"


def test_authed_url_no_token_unchanged() -> None:
    assert _authed_url("https://github.com/acme/api.git", None) == "https://github.com/acme/api.git"


def test_authed_url_non_https_unchanged() -> None:
    assert _authed_url("git@github.com:acme/api.git", "TOK") == "git@github.com:acme/api.git"


async def test_clone_success_sets_local_path_and_keeps_url_token_free(tmp_path: Path) -> None:
    captured: list[list[str]] = []

    async def fake_runner(args: list[str], timeout: float) -> int:
        captured.append(args)
        return 0

    ref = await clone_repository(
        _REPO,
        dest_root=tmp_path,
        token="SECRET_TOK",  # noqa: S106  # test token, not a real credential
        runner=fake_runner,
    )
    assert ref is not None
    assert ref.local_path == str(tmp_path / "github" / "acme" / "api")
    # Returned ref keeps the original token-free clone_url.
    assert ref.clone_url == "https://github.com/acme/api.git"
    assert "SECRET_TOK" not in repr(ref)
    # The token only appears in the (transient) subprocess args, not persisted.
    assert any("x-access-token:SECRET_TOK@" in arg for arg in captured[0])
    assert captured[0][:3] == ["git", "clone", "--depth"]


async def test_clone_failure_returns_none(tmp_path: Path) -> None:
    async def failing_runner(args: list[str], timeout: float) -> int:
        return 128

    ref = await clone_repository(_REPO, dest_root=tmp_path, runner=failing_runner)
    assert ref is None


async def test_git_absent_degrades_gracefully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(repo_clone.shutil, "which", lambda _name: None)
    ref = await clone_repository(_REPO, dest_root=tmp_path)  # no runner → checks git
    assert ref is None
