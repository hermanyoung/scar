"""CLI command: eval — run CWE detection evaluation tests."""
from __future__ import annotations

import asyncio
from pathlib import Path

import click

from security_review.cli import PROJECT_ROOT, _setup_logging, cli


@cli.command("eval")
@click.option("--eval-dir", "eval_path", default=None,
              type=click.Path(exists=True),
              help="Run eval tests from this directory [default: eval/].")
@click.option("--target", default=None,
              type=click.Path(exists=True),
              help="Run application integration tests against this repo.")
@click.option("--baseline", default=None,
              type=click.Path(exists=True),
              help="Path to baseline manifest YAML for application tests.")
@click.option("--provider", "providers", multiple=True,
              help="Provider string, e.g. copilot:claude-opus (repeatable).")
@click.option("--cwes", default=None,
              help="Comma-separated CWE IDs to test (default: all).")
@click.option("--format", "output_format", default="table",
              type=click.Choice(["table", "json"]),
              help="Output format [default: table].")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def eval_cmd(eval_path, target, baseline, providers, cwes, output_format, verbose, debug):
    """Run CWE detection evaluation tests."""
    _setup_logging(verbose or not debug, debug, quiet=False,
                   json_logs=False, no_file_log=True)

    from security_review.config import load_config

    cfg = load_config()

    provider_list = list(providers) if providers else [cfg.llm.provider_model]

    cwe_filter: set[str] | None = None
    if cwes:
        cwe_filter = {c.strip().replace("CWE-", "").replace("cwe-", "").lstrip("0")
                      for c in cwes.split(",") if c.strip()}

    run_eval = eval_path is not None or target is None
    run_app = target is not None

    if run_eval:
        eval_dir = Path(eval_path) if eval_path else PROJECT_ROOT / "eval"
        if not eval_dir.exists():
            click.echo(f"Eval directory not found: {eval_dir}", err=True)
            raise SystemExit(1)

    if run_app:
        target_path = Path(target).resolve()
        if baseline is None:
            click.echo("--baseline is required when --target is specified.", err=True)
            raise SystemExit(1)
        baseline_path = Path(baseline)

    import json as json_mod

    all_summaries: list = []
    any_failure = False

    async def _run_all():
        nonlocal any_failure
        from security_review.evaluation import (
            run_application_tests,
            run_eval_tests,
        )

        for prov in provider_list:
            if run_eval:
                summary = await run_eval_tests(
                    eval_dir, prov, cwe_filter=cwe_filter,
                )
                all_summaries.append(("eval", summary))
                if summary.failed > 0 or summary.false_positives > 0:
                    any_failure = True

            if run_app:
                summary = await run_application_tests(
                    target_path, baseline_path, prov, cwe_filter=cwe_filter,
                )
                all_summaries.append(("application", summary))
                if summary.failed > 0:
                    any_failure = True

    try:
        asyncio.run(_run_all())
    except KeyboardInterrupt:
        click.echo("\nInterrupted.", err=True)
        raise SystemExit(130)
    except Exception as e:
        click.echo(f"\nEvaluation failed: {e}", err=True)
        raise SystemExit(1)

    if output_format == "json":
        data = [
            {"layer": layer, **summary.model_dump()}
            for layer, summary in all_summaries
        ]
        click.echo(json_mod.dumps(data, indent=2))
    else:
        from security_review.evaluation import print_eval_table
        print_eval_table(all_summaries)

    raise SystemExit(1 if any_failure else 0)
