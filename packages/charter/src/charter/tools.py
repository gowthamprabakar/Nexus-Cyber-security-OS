"""Tool registry — version-pinned, whitelist-checked dispatch."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from charter.exceptions import ToolNotPermitted


@dataclass(frozen=True)
class ToolMeta:
    func: Callable[..., Any]
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
        self._tools[name] = ToolMeta(func=func, version=version, cloud_calls=cloud_calls)

    def call(self, name: str, *, permitted: list[str], **kwargs: Any) -> Any:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        if name not in permitted:
            raise ToolNotPermitted(tool=name, permitted=permitted)
        return self._tools[name].func(**kwargs)

    def version(self, name: str) -> str:
        return self._tools[name].version

    def cloud_calls(self, name: str) -> int:
        return self._tools[name].cloud_calls

    def known_tools(self) -> list[str]:
        return sorted(self._tools.keys())
