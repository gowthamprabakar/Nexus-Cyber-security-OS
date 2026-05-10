"""`eval-framework` CLI — run / compare / gate.

Per F.2 plan Task 13. Three subcommands cover the three real-world
workflows:

- `run` — execute a suite via a registered `EvalRunner` and write a JSON
  SuiteResult to disk.
- `compare` — diff two saved SuiteResults and write a markdown
  ComparisonReport.
- `gate` — apply a YAML-defined `Gate` to a saved SuiteResult; exits
  non-zero when any threshold blows.

Runners are resolved through the `nexus_eval_runners` setuptools
entry-point group. cloud-posture's pyproject registers
`cloud_posture = "cloud_posture.eval_runner:CloudPostureEvalRunner"`
in F.2 Task 14; this CLI just looks up the name.
"""

from __future__ import annotations

import asyncio
import sys
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

import click
import yaml
from charter.llm import LLMProvider

from eval_framework.cases import load_cases
from eval_framework.compare import diff_results
from eval_framework.gate import Gate, apply_gate
from eval_framework.render_json import (
    comparison_to_json,
    suite_from_json,
    suite_to_json,
)
from eval_framework.render_md import (
    render_comparison_md,
    render_gate_md,
)
from eval_framework.runner import EvalRunner
from eval_framework.suite import run_suite

ENTRY_POINT_GROUP = "nexus_eval_runners"


# ---------------------------- runner registry ----------------------------


def _resolve_runner(name: str) -> EvalRunner:
    """Look up a registered runner by name via setuptools entry points."""
    eps = entry_points(group=ENTRY_POINT_GROUP)
    for ep in eps:
        if ep.name == name:
            cls = ep.load()
            return cls()  # type: ignore[no-any-return]
    raise KeyError(f"no runner named {name!r} in entry-point group {ENTRY_POINT_GROUP!r}")


def _resolve_provider(provider_label: str | None, model_pin: str | None) -> LLMProvider | None:
    """Build an LLMProvider from CLI flags. None when no flag was given.

    Honors a small set of well-known labels; everything else is delegated
    to env-var-driven config in the future. Today we keep this minimal so
    Task 14's cloud-posture migration doesn't have to replumb provider
    selection at the CLI layer.
    """
    if provider_label is None:
        return None
    label = provider_label.strip().lower()
    if label == "ollama":
        from charter.llm_openai_compat import OpenAICompatibleProvider

        del model_pin  # threaded through metadata only; provider doesn't bind it
        return OpenAICompatibleProvider.for_ollama()
    if label == "anthropic":
        from charter.llm import ModelTier
        from charter.llm_anthropic import AnthropicProvider

        return AnthropicProvider(model_class=ModelTier.WORKHORSE)
    raise click.UsageError(
        f"unknown --provider {provider_label!r}; supported: ollama, anthropic. "
        "For other providers use the Python API."
    )


# ---------------------------- click group --------------------------------


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option()
def cli() -> None:
    """Nexus eval-framework — run / compare / gate eval suites."""


@cli.command("run")
@click.option(
    "--runner",
    "runner_name",
    required=True,
    help="Registered runner name (entry-point group nexus_eval_runners).",
)
@click.option(
    "--cases",
    "cases_dir",
    required=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Directory of *.yaml case files.",
)
@click.option(
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the SuiteResult JSON.",
)
@click.option(
    "--provider",
    "provider_label",
    default=None,
    help="Optional LLM provider (anthropic | ollama).",
)
@click.option("--model", "model_pin", default=None, help="Model pin to thread through.")
def run_cmd(
    runner_name: str,
    cases_dir: Path,
    output_path: Path,
    provider_label: str | None,
    model_pin: str | None,
) -> None:
    """Execute a suite and write SuiteResult JSON."""
    try:
        runner = _resolve_runner(runner_name)
    except KeyError as e:
        click.echo(str(e), err=True)
        raise click.exceptions.Exit(code=2) from None

    cases = load_cases(cases_dir)
    llm_provider = _resolve_provider(provider_label, model_pin)

    metadata: dict[str, Any] = {}
    if model_pin:
        metadata["model_pin_request"] = model_pin

    suite = asyncio.run(run_suite(cases, runner, llm_provider=llm_provider, metadata=metadata))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(suite_to_json(suite), encoding="utf-8")

    click.echo(f"{suite.passed}/{suite.total} passed ({suite.pass_rate * 100:.1f}%)")
    click.echo(f"wrote suite → {output_path}")


@cli.command("compare")
@click.argument(
    "baseline",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument(
    "candidate",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--output",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the markdown comparison report.",
)
@click.option(
    "--json-output",
    "json_output_path",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Optional path for the JSON ComparisonReport.",
)
def compare_cmd(
    baseline: Path,
    candidate: Path,
    output_path: Path,
    json_output_path: Path | None,
) -> None:
    """Diff two saved suites; emit markdown (and optional JSON) report."""
    baseline_suite = suite_from_json(baseline.read_bytes())
    candidate_suite = suite_from_json(candidate.read_bytes())
    report = diff_results(baseline_suite, candidate_suite)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_comparison_md(report), encoding="utf-8")

    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        json_output_path.write_text(comparison_to_json(report), encoding="utf-8")

    click.echo(
        f"{report.summary.regressions_count} regression(s), "
        f"{report.summary.improvements_count} improvement(s) "
        f"across {report.summary.total_cases} case(s)"
    )
    click.echo(f"wrote markdown → {output_path}")
    if json_output_path is not None:
        click.echo(f"wrote json → {json_output_path}")


@cli.command("gate")
@click.argument(
    "suite_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--config",
    "config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="YAML gate definition.",
)
@click.option(
    "--baseline",
    "baseline_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Optional baseline suite for regression / token-delta gates.",
)
def gate_cmd(suite_path: Path, config_path: Path, baseline_path: Path | None) -> None:
    """Apply a `Gate` to a saved suite. Exits non-zero on failure."""
    suite = suite_from_json(suite_path.read_bytes())
    gate = Gate.model_validate(yaml.safe_load(config_path.read_text(encoding="utf-8")))
    baseline = suite_from_json(baseline_path.read_bytes()) if baseline_path is not None else None

    result = apply_gate(suite, gate, baseline=baseline)
    click.echo(render_gate_md(result, suite))

    if not result.passed:
        raise click.exceptions.Exit(code=1)


# ---------------------------- public main --------------------------------


def main() -> int:
    """`[project.scripts]` entry point. Click's group raises SystemExit."""
    cli(standalone_mode=True)
    return 0  # unreachable in practice — click exits via SystemExit


if __name__ == "__main__":
    sys.exit(main())
