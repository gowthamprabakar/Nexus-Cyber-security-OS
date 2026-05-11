"""Tests for `runtime_threat.tools.osquery.osquery_run`.

The subprocess is mocked via `monkeypatch` on `asyncio.create_subprocess_exec`
so the tests don't depend on a real `osqueryi` binary being installed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from runtime_threat.tools import osquery as osquery_mod
from runtime_threat.tools.osquery import OsqueryError, OsqueryResult, osquery_run


class _FakeProcess:
    """Stand-in for `asyncio.subprocess.Process` returned by `create_subprocess_exec`."""

    def __init__(
        self,
        *,
        stdout: bytes = b"[]",
        stderr: bytes = b"",
        returncode: int = 0,
        hang: bool = False,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode: int | None = returncode
        self._hang = hang
        self.killed = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._hang:
            await asyncio.sleep(60)  # will be killed by wait_for
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode or 0


def _patch_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeProcess,
) -> None:
    async def fake_create(*args: Any, **kwargs: Any) -> _FakeProcess:
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def _patch_which(monkeypatch: pytest.MonkeyPatch, resolved: str | None) -> None:
    """Pretend `shutil.which(osqueryi)` resolved to a given path."""
    monkeypatch.setattr(osquery_mod.shutil, "which", lambda _: resolved)


# ---------------------------- happy path ---------------------------------


@pytest.mark.asyncio
async def test_returns_parsed_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = json.dumps([{"pid": "1234", "name": "init"}, {"pid": "2345", "name": "sshd"}])
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(monkeypatch, _FakeProcess(stdout=canned.encode()))

    result = await osquery_run(sql="SELECT pid, name FROM processes LIMIT 2")

    assert isinstance(result, OsqueryResult)
    assert result.sql == "SELECT pid, name FROM processes LIMIT 2"
    assert result.rows == (
        {"pid": "1234", "name": "init"},
        {"pid": "2345", "name": "sshd"},
    )


@pytest.mark.asyncio
async def test_empty_result_set_returns_empty_tuple(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(monkeypatch, _FakeProcess(stdout=b"[]"))

    result = await osquery_run(sql="SELECT 1 WHERE 0")
    assert result.rows == ()


@pytest.mark.asyncio
async def test_blank_stdout_treated_as_empty_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Some osqueryi builds emit nothing for a zero-row result."""
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(monkeypatch, _FakeProcess(stdout=b""))

    result = await osquery_run(sql="SELECT 1 WHERE 0")
    assert result.rows == ()


@pytest.mark.asyncio
async def test_coerces_non_string_values_to_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """osquery returns strings by default, but tolerate numeric values too."""
    canned = json.dumps([{"pid": 1234, "name": "init", "uid": 0}])
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(monkeypatch, _FakeProcess(stdout=canned.encode()))

    result = await osquery_run(sql="SELECT pid, name, uid FROM processes")
    assert result.rows == ({"pid": "1234", "name": "init", "uid": "0"},)


# ---------------------------- error paths --------------------------------


@pytest.mark.asyncio
async def test_missing_binary_raises_osquery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_which(monkeypatch, None)
    with pytest.raises(OsqueryError, match="osqueryi binary not found"):
        await osquery_run(sql="SELECT 1")


@pytest.mark.asyncio
async def test_non_zero_exit_raises_osquery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(
        monkeypatch,
        _FakeProcess(returncode=1, stderr=b"syntax error near 'FORM'"),
    )

    with pytest.raises(OsqueryError, match=r"exited 1.*syntax error"):
        await osquery_run(sql="SELECT 1 FORM processes")


@pytest.mark.asyncio
async def test_malformed_json_raises_osquery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(monkeypatch, _FakeProcess(stdout=b"not json at all"))

    with pytest.raises(OsqueryError, match="emitted non-JSON output"):
        await osquery_run(sql="SELECT 1")


@pytest.mark.asyncio
async def test_json_object_not_array_raises_osquery_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`osqueryi --json` always emits an array; an object is a malformed result."""
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(monkeypatch, _FakeProcess(stdout=b'{"oops": "object"}'))

    with pytest.raises(OsqueryError, match="expected JSON array"):
        await osquery_run(sql="SELECT 1")


@pytest.mark.asyncio
async def test_timeout_kills_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(hang=True)
    _patch_which(monkeypatch, "/usr/bin/osqueryi")
    _patch_subprocess(monkeypatch, process)

    with pytest.raises(OsqueryError, match=r"timed out after"):
        await osquery_run(sql="SELECT 1", timeout_sec=0.01)

    assert process.killed is True


# ---------------------------- shape invariant ----------------------------


def test_osquery_result_is_frozen() -> None:
    import dataclasses

    r = OsqueryResult(sql="x", rows=())
    assert dataclasses.is_dataclass(r)
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.sql = "mutated"  # type: ignore[misc]
