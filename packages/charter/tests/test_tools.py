"""Tests for ToolRegistry."""

import pytest
from charter.exceptions import ToolNotPermitted
from charter.tools import ToolRegistry


def echo_tool(value: str) -> str:
    return value


def add_tool(a: int, b: int) -> int:
    return a + b


def test_register_and_call() -> None:
    reg = ToolRegistry()
    reg.register("echo", echo_tool, version="1.0.0", cloud_calls=0)
    result = reg.call("echo", permitted=["echo"], value="hi")
    assert result == "hi"


def test_call_unregistered_tool_raises() -> None:
    reg = ToolRegistry()
    with pytest.raises(KeyError):
        reg.call("nonexistent", permitted=["nonexistent"])


def test_call_unpermitted_tool_raises() -> None:
    reg = ToolRegistry()
    reg.register("delete_user", lambda **_: None, version="1.0.0", cloud_calls=1)
    with pytest.raises(ToolNotPermitted) as exc_info:
        reg.call("delete_user", permitted=["read_user"])
    assert exc_info.value.tool == "delete_user"


def test_versioning() -> None:
    reg = ToolRegistry()
    reg.register("v_tool", lambda: None, version="1.2.3", cloud_calls=0)
    assert reg.version("v_tool") == "1.2.3"


def test_cloud_calls_metadata() -> None:
    reg = ToolRegistry()
    reg.register("aws_s3_describe", lambda: None, version="1.0.0", cloud_calls=1)
    assert reg.cloud_calls("aws_s3_describe") == 1
