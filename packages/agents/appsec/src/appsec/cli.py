"""AppSec Agent CLI (D.14 v0.1).

``appsec run --contract <path>`` runs repository discovery against an
ExecutionContract and writes the artifacts to the contract workspace. v0.1 uses
the empty static connector (deterministic no-op discovery); live SCM connectors
+ flags land in B-1 PR2.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract

from appsec.agent import run as agent_run


@click.group()
def main() -> None:
    """Nexus AppSec Agent (D.14)."""


@main.command("run")
@click.option(
    "--contract",
    "contract_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to an ExecutionContract YAML.",
)
def run_cmd(contract_path: Path) -> None:
    """Run AppSec repository discovery against an ExecutionContract YAML."""
    contract = load_contract(contract_path)
    inventory = asyncio.run(agent_run(contract))
    click.echo(f"agent: {inventory.agent} (v{inventory.agent_version})")
    click.echo(f"customer: {inventory.customer_id}")
    click.echo(f"run_id: {inventory.run_id}")
    click.echo(f"repositories discovered: {inventory.total}")


if __name__ == "__main__":
    main()
