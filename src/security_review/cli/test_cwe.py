"""CLI command: test-cwe — run a single LLM holistic CWE check."""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import click

from security_review.cli.app import PROJECT_ROOT, _setup_logging, cli


def _print_selection_comparison(check, entries, target_path: Path) -> None:
    """Report graph-walk vs keyword-only file selection for one CWE check.

    Read-only comparison, no LLM call — for measuring whether call-graph
    selection actually finds files keyword matching misses (plan 010 Phase 3).
    """
    from code_analysis import analyze, compute_call_graph_pagerank
    from code_analysis.call_graph import build_call_graph

    from security_review.checks import select_files_for_check, select_files_for_cwe
    from security_review.passes.pipeline import find_csharp_project

    metrics = analyze(target_path, include_graph=True)
    python_files = [target_path / f.path for f in entries if f.language == "python"]
    csharp_solution = find_csharp_project(target_path)

    graph = build_call_graph(
        target_path, metrics.modules,
        python_files=python_files or None, csharp_solution=csharp_solution,
    )
    pagerank = compute_call_graph_pagerank(graph)

    graph_selected, telemetry = select_files_for_cwe(check, entries, call_graph=graph, pagerank=pagerank)
    keyword_selected = select_files_for_check(check, entries)

    graph_paths = {f.path for f in graph_selected}
    keyword_paths = {f.path for f in keyword_selected}
    graph_only = sorted(graph_paths - keyword_paths)
    keyword_only = sorted(keyword_paths - graph_paths)
    both = sorted(graph_paths & keyword_paths)

    click.echo(f"\n{check.display_name} — file selection comparison")
    click.echo(f"  Method used:    {telemetry.method}")
    click.echo(f"  Call graph:     {len(graph.nodes)} nodes, {len(graph.call_edges)} call edges")
    click.echo()
    click.echo(f"  Graph-only ({len(graph_only)}) — keyword matching missed these:")
    for p in graph_only[:20]:
        click.echo(f"    + {p}")
    click.echo()
    click.echo(f"  Keyword-only ({len(keyword_only)}) — graph walk missed these:")
    for p in keyword_only[:20]:
        click.echo(f"    + {p}")
    click.echo()
    click.echo(f"  Both ({len(both)} files)")


@cli.command("test-cwe")
@click.option("--cwe", required=True, help="CWE number (e.g. 863 or CWE-863).")
@click.option("--target", required=True, type=click.Path(exists=True),
              help="Path to codebase root.")
@click.option("--provider", default=None,
              help="LLM provider:model (default: from config).")
@click.option("--trace", is_flag=True,
              help="Write trace file to var/output/.")
@click.option("--temperature", type=float, default=None,
              help="Override LLM temperature (0.0=deterministic, 1.0=creative).")
@click.option("--compare-selection", is_flag=True,
              help="Compare graph-walk vs keyword-only file selection and exit (no LLM call).")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def test_cwe(cwe, target, provider, trace, temperature, compare_selection, verbose, debug):
    """Run a single LLM holistic CWE check against a target."""
    _setup_logging(verbose or not debug, debug, quiet=False,
                   json_logs=False, no_file_log=True)

    from security_review.config import load_config
    from security_review.checks import load_cwe_checks, select_files_for_check, select_files_for_cwe
    from security_review.passes.inventory import discover_files

    cfg = load_config()
    if temperature is not None:
        cfg = cfg.model_copy(update={"llm": cfg.llm.model_copy(update={"temperature": temperature})})
    target_path = Path(target).resolve()

    if not target_path.exists():
        click.echo(f"Target not found: {target_path}", err=True)
        raise SystemExit(1)

    # Find the CWE check
    cwe_num = cwe.replace("CWE-", "").replace("cwe-", "").lstrip("0")
    checks = load_cwe_checks()
    matched = [c for c in checks if c.cwe_id == cwe_num]
    if not matched:
        click.echo(f"CWE-{cwe_num} not found in taxonomy or has no LLM check defined.", err=True)
        click.echo(f"Available LLM checks: {', '.join(f'CWE-{c.cwe_id}' for c in checks)}", err=True)
        raise SystemExit(1)
    check = matched[0]

    # File discovery — same code path as the pipeline (Pass 1)
    entries = discover_files(target_path, cfg.sast.scanner_max_file_size_bytes)

    if compare_selection:
        _print_selection_comparison(check, entries, target_path)
        return

    relevant = select_files_for_check(check, entries)
    file_paths = [f.path for f in relevant]

    if not file_paths:
        click.echo(f"No relevant files for {check.display_name}", err=True)
        raise SystemExit(1)

    click.echo(f"\n{check.display_name}")
    click.echo(f"  Target:   {target_path}")
    click.echo(f"  Files:    {len(file_paths)}")
    for fp in file_paths[:10]:
        click.echo(f"    - {fp}")
    if len(file_paths) > 10:
        click.echo(f"    ... and {len(file_paths) - 10} more")
    click.echo()

    # Run the check
    model_string = provider or cfg.llm.provider_model

    async def _run():
        from security_review.providers import build_model
        from security_review.model_capabilities import supports_native_json
        from security_review.model_settings import build_model_settings
        from security_review.passes.state import PipelineState
        from security_review.passes.holistic import run_single_check
        from security_review.sarif.merger import merge_sarif
        from security_review.models.inventory import FileManifest

        model = build_model(model_string, llm_config=cfg.llm)
        run_cfg = cfg
        if trace:
            # output_dir derives from review.output_sarif, which defaults to a
            # bare filename — left alone that puts traces/ in the project root.
            # Give the run its own var/output directory, as `review` does.
            run_dir = f"var/output/{datetime.now().strftime('%Y-%m-%d')}-cwe-{cwe_num}-{uuid4().hex[:8]}"
            run_cfg = cfg.model_copy(update={
                "review": cfg.review.model_copy(
                    update={"output_sarif": f"{run_dir}/security-report.sarif"},
                ),
            })

        state = PipelineState(
            config=run_cfg,
            target_path=target_path,
            work_dir=PROJECT_ROOT,
            trace_enabled=trace,
        )
        state.manifest = FileManifest(
            files=entries,
            total_files=len(entries),
            total_tokens=sum(e.estimated_tokens for e in entries),
            languages={},
        )
        state.sast_sarif = merge_sarif([])

        # Mirror run_holistic exactly. Without these two the benchmark measures
        # a configuration nobody runs: no reasoning effort or prompt caching,
        # and prompted markdown parsing even for models that enforce the schema
        # natively — so a golden score would not describe the real pipeline.
        result = await run_single_check(
            check=check,
            file_paths=file_paths,
            state=state,
            model=model,
            model_string=model_string,
            model_settings=build_model_settings(model_string, run_cfg.llm),
            native_json=supports_native_json(model),
        )

        if result is None:
            click.echo("  Check failed — no result returned.")
            return

        findings, files_reviewed, parse_failed = result
        click.echo(f"  Findings: {len(findings)}")
        click.echo(f"  Files reviewed: {len(files_reviewed)}")
        click.echo()

        if not findings:
            click.echo(click.style("  No findings.", dim=True))
        else:
            for f in findings:
                sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(f.severity, "white")
                click.echo(
                    click.style(f"  [{f.severity}]", fg=sev_color) +
                    f" {f.file_path}:{f.line_number}"
                )
                click.echo(f"    {f.title}")
                if f.evidence:
                    for line in f.evidence.strip().split("\n")[:5]:
                        click.echo(click.style(f"    | {line}", dim=True))
                click.echo()

    asyncio.run(_run())
