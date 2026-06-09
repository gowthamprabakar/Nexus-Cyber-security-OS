"""Tool registry — version-pinned, whitelist-checked, proxy-gated dispatch.

A registered tool is wrapped in a :class:`_ProxiedTool`. The proxy executes the
underlying callable only while a charter-mediated dispatch is active (the
``_IN_DISPATCH`` re-entrancy flag, set by :meth:`ToolRegistry.call`). Invoked
any other way it raises :class:`DirectInvocationBlocked`. This makes
``permitted_tools`` a hard boundary rather than an opt-in convention: the
registry-held callable physically cannot run outside the gate (ADR-016).
"""

from __future__ import annotations

from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from charter.exceptions import DirectInvocationBlocked, ToolNotPermitted

# True only for the duration of a single ToolRegistry.call() dispatch. The proxy
# checks it synchronously at call time (which, for async tools, is coroutine
# *creation* time — so the guard fires before the coroutine is ever awaited).
_IN_DISPATCH: ContextVar[bool] = ContextVar("nexus_tool_in_dispatch", default=False)


class _ProxiedTool:
    """Wraps a tool callable so it runs only inside a charter dispatch."""

    __slots__ = ("_func", "_name")

    def __init__(self, name: str, func: Callable[..., Any]) -> None:
        self._name = name
        self._func = func

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if not _IN_DISPATCH.get():
            raise DirectInvocationBlocked(self._name)
        return self._func(*args, **kwargs)

    @property
    def name(self) -> str:
        return self._name


@dataclass(frozen=True)
class ToolMeta:
    proxy: _ProxiedTool
    version: str
    cloud_calls: int  # how many cloud-API calls this tool makes per invocation


class ToolRegistry:
    """Holds the universe of callable tools. Each call is permission-checked."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolMeta] = {}

    def register(
        self, name: str, func: Callable[..., Any], *, version: str, cloud_calls: int
    ) -> None:
        if name in self._tools:
            raise ValueError(f"tool {name!r} already registered")
        self._tools[name] = ToolMeta(
            proxy=_ProxiedTool(name, func), version=version, cloud_calls=cloud_calls
        )

    def call(self, name: str, *, permitted: list[str], **kwargs: Any) -> Any:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        if name not in permitted:
            raise ToolNotPermitted(tool=name, permitted=permitted)
        proxy = self._tools[name].proxy
        token = _IN_DISPATCH.set(True)
        try:
            return proxy(**kwargs)
        finally:
            _IN_DISPATCH.reset(token)

    def version(self, name: str) -> str:
        return self._tools[name].version

    def cloud_calls(self, name: str) -> int:
        return self._tools[name].cloud_calls

    def known_tools(self) -> list[str]:
        return sorted(self._tools.keys())
