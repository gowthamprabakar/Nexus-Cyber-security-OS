"""Charter CLI: validate contracts, verify audit logs."""

from __future__ import annotations

from pathlib import Path

import click

from charter.contract import load_contract
from charter.verifier import verify_audit_log


@click.group()
@click.version_option()
def main() -> None:
    """Charter — execution contract validation and audit log verification."""


@main.command()
@click.argument("contract_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate(contract_path: Path) -> None:
    """Validate an execution contract YAML file."""
    try:
        contract = load_contract(contract_path)
    except Exception as e:
        click.echo(f"INVALID: {e}", err=True)
        raise SystemExit(1) from e
    click.echo(f"VALID: {contract.target_agent} ({contract.delegation_id})")


@main.group()
def audit() -> None:
    """Audit log commands."""


@audit.command()
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def verify(log_path: Path) -> None:
    """Verify an audit log's hash chain integrity."""
    result = verify_audit_log(log_path)
    if result.valid:
        click.echo(f"VALID: {result.entries_checked} entries, chain intact")
    else:
        click.echo(f"INVALID: chain broken at entry {result.broken_at}", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
