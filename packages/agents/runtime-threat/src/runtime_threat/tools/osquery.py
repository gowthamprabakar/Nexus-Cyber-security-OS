"""OSQuery subprocess wrapper — runs a SQL query against `osqueryi --json`.

OSQuery turns OS state (processes, listening sockets, kernel modules,
file integrity, etc.) into a SQL-queryable database. Invoking
`osqueryi --json "SELECT pid, name FROM processes LIMIT 5"` emits a
JSON array of rows where every value is a string:

    [
      {"pid": "1234", "name": "init"},
      {"pid": "2345", "name": "sshd"},
      ...
    ]

Per ADR-005 the subprocess invocation goes through
`asyncio.create_subprocess_exec`. Live OSQuery (distributed scheduler,
fleet management) is deferred to Phase 1c per the D.3 plan.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime


class OsqueryError(RuntimeError):
    """`osqueryi` exited non-zero, timed out, or produced unparseable output."""


@dataclass(frozen=True, slots=True)
class OsqueryResult:
    """Result of a single `osqueryi --json` invocation.

    `rows` is a tuple of string-valued dicts — OSQuery returns every
    column as a string by default. Type coercion (e.g. int(`pid`)) is
    the normalizer's job.
    """

    sql: str
    rows: tuple[dict[str, str], ...]
    ran_at: datetime = field(default_factory=lambda: datetime.now(UTC))


async def osquery_run(
    *,
    sql: str,
    timeout_sec: float = 30.0,
    osqueryi_binary: str = "osqueryi",
) -> OsqueryResult:
    """Run a single SQL query against `osqueryi --json`.

    Args:
        sql: The SQL query to execute. Passed verbatim to `osqueryi`.
        timeout_sec: Wall-clock timeout for the subprocess.
        osqueryi_binary: Name or path of the osquery interactive binary;
            resolved via `shutil.which` when not absolute.

    Raises:
        OsqueryError: when the binary is missing, the subprocess exits
            non-zero, the output is not JSON, or the timeout fires.
    """
    binary = shutil.which(osqueryi_binary) or osqueryi_binary
    if not _binary_looks_runnable(binary):
        raise OsqueryError(f"osqueryi binary not found: {osqueryi_binary}")

    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            "--json",
            sql,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise OsqueryError(f"osqueryi binary not found: {osqueryi_binary}") from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise OsqueryError(f"osqueryi timed out after {timeout_sec}s") from exc

    if proc.returncode != 0:
        raise OsqueryError(
            f"osqueryi exited {proc.returncode}: {stderr_b.decode(errors='replace').strip()}"
        )

    raw = stdout_b.decode(errors="replace").strip() or "[]"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OsqueryError(f"osqueryi emitted non-JSON output: {raw[:200]}") from exc

    if not isinstance(parsed, list):
        raise OsqueryError(f"osqueryi expected JSON array, got {type(parsed).__name__}")

    rows: list[dict[str, str]] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        rows.append({str(k): str(v) for k, v in entry.items()})

    return OsqueryResult(sql=sql, rows=tuple(rows))


def _binary_looks_runnable(path: str) -> bool:
    """True when shutil.which resolved an absolute path (covers PATH discovery)."""
    from pathlib import Path

    return Path(path).is_absolute()


__all__ = ["OsqueryError", "OsqueryResult", "osquery_run"]
