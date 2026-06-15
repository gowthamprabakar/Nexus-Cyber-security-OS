"""Shallow git clone of discovered repos → local_path for scanning (D.14, B-1 PR6).

The SCM connectors (B-1 PR5) list repos as metadata (clone_url, no local_path);
Checkov/gitleaks need files on disk. This clones each repo shallowly (depth 1) into
a dest directory and returns a ``RepoRef`` with ``local_path`` set, so the existing
scan loop picks it up.

**Token handling (hard).** For private repos the token is injected into the clone
URL (``https://x-access-token:<token>@host/...``) at call time and is NEVER logged,
returned, or stored on the RepoRef (the returned ref keeps the original
token-free ``clone_url``). Operator-provisioned-binary model: ``git`` absent →
clean skip (returns ``None``), not a crash.
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from appsec.schemas import RepoRef

#: Injectable clone runner: (args, timeout_sec) -> return code. Default shells git.
CloneRunner = Callable[[list[str], float], Awaitable[int]]


async def _default_clone_runner(args: list[str], timeout_sec: float) -> int:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return 124
    return proc.returncode if proc.returncode is not None else 1


def _authed_url(clone_url: str, token: str | None) -> str:
    """Inject the token as a userinfo component for https clone URLs.

    Only https URLs are rewritten; anything else is returned unchanged. The
    resulting URL is used ONLY as a subprocess arg — never logged or persisted.
    """
    if not token:
        return clone_url
    parts = urlsplit(clone_url)
    if parts.scheme != "https":
        return clone_url
    netloc = f"x-access-token:{token}@{parts.hostname or ''}"
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


async def clone_repository(
    repo: RepoRef,
    *,
    dest_root: Path | str,
    token: str | None = None,
    depth: int = 1,
    runner: CloneRunner | None = None,
    timeout_sec: float = 300.0,
) -> RepoRef | None:
    """Shallow-clone ``repo`` under ``dest_root``; return a RepoRef with local_path.

    Returns ``None`` when git is absent or the clone fails (the caller keeps the
    original token-free ref → the repo is simply not scanned). The returned ref
    carries the original ``clone_url`` (no embedded token).
    """
    if runner is None and shutil.which("git") is None:
        return None
    dest = Path(dest_root) / repo.host / repo.owner / repo.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["git", "clone", "--depth", str(depth), _authed_url(repo.clone_url, token), str(dest)]
    return_code = await (runner or _default_clone_runner)(args, timeout_sec)
    if return_code != 0:
        return None
    return repo.model_copy(update={"local_path": str(dest)})


__all__ = ["CloneRunner", "clone_repository"]
