"""Tests for WorkspaceManager."""

from pathlib import Path

from charter.workspace import WorkspaceManager


def test_workspace_creates_dirs(tmp_path: Path) -> None:
    workspace = tmp_path / "workspaces" / "cust" / "agent" / "run123"
    persistent = tmp_path / "persistent" / "cust" / "agent"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    assert workspace.is_dir()
    assert (persistent / "episodic").is_dir()
    assert (persistent / "procedural").is_dir()
    assert (persistent / "semantic").is_dir()


def test_workspace_write_output(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    mgr.write_output("findings.json", b'{"x": 1}')
    assert (workspace / "findings.json").read_bytes() == b'{"x": 1}'


def test_workspace_check_required_outputs_missing(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    missing = mgr.missing_outputs(["findings.json", "summary.md"])
    assert missing == ["findings.json", "summary.md"]


def test_workspace_check_required_outputs_partial(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    mgr.write_output("findings.json", b"{}")
    missing = mgr.missing_outputs(["findings.json", "summary.md"])
    assert missing == ["summary.md"]


def test_workspace_disk_usage_tracked(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    persistent = tmp_path / "p"
    mgr = WorkspaceManager(workspace=workspace, persistent_root=persistent)
    mgr.setup()
    mgr.write_output("a.txt", b"x" * 1024)
    mgr.write_output("b.txt", b"y" * 2048)
    assert mgr.bytes_written() == 3072
