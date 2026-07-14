"""CLI command: review — run the security review pipeline."""
from __future__ import annotations

import asyncio
import json
import time as _time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import click

from security_review.cli.app import PROJECT_ROOT, _setup_logging, cli

_BAND_AT_OR_ABOVE = {
    "urgent":   ("URGENT",),
    "elevated": ("URGENT", "ELEVATED"),
    "moderate": ("URGENT", "ELEVATED", "MODERATE"),
    "low":      ("URGENT", "ELEVATED", "MODERATE", "LOW"),
}


def resolve_exit_code(report_data, fail_on: str | None, fail_on_degraded: bool) -> int:
    """0 = pass; 3 = findings at/above threshold; 4 = degraded run."""
    if report_data is None:
        return 0
    if fail_on:
        counts = {"URGENT": report_data.urgent, "ELEVATED": report_data.elevated,
                  "MODERATE": report_data.moderate, "LOW": report_data.low}
        if any(counts[b] > 0 for b in _BAND_AT_OR_ABOVE[fail_on]):
            return 3
    if fail_on_degraded and report_data.degradations:
        return 4
    return 0


@cli.command()
@click.option("--target", default=None, type=click.Path(exists=True),
              help="Path to codebase root. Required unless --resume is given.")
@click.option("--mode", default=None,
              type=click.Choice(["full", "sast", "sast-triage"]),
              help="Pipeline mode (default: full).")
@click.option("--provider", default=None,
              help="LLM provider:model (e.g. copilot:claude-opus-4.6).")
@click.option("--budget", type=float, default=None,
              help="Max LLM spend in USD.")
@click.option("--output", default=None,
              help="Output SARIF path (default: var/output/{date}-{target}-{id}/).")
@click.option("--summary", default=None,
              help="Output markdown summary path.")
@click.option("--format", "report_format", default=None,
              help="Report format: summary, full, json, csv, all (comma-separated).")
@click.option("--config", "config_path", default=None,
              type=click.Path(exists=True),
              help="Override config YAML path.")
@click.option("--resume", "resume", default=None,
              type=click.Path(exists=True, file_okay=False),
              help="Resume a previous run from its output directory "
                   "(var/output/{date}-{target}-{id}/). Reuses that run's "
                   "config verbatim — conflicts with --target/--mode/--provider/etc.")
@click.option("--stream", "stream", is_flag=True,
              help="Write security-report.partial.sarif after each LLM pass.")
@click.option("--verbose", "-v", is_flag=True,
              help="Show batch/tool detail and structlog output.")
@click.option("--debug", is_flag=True,
              help="DEBUG-level structlog + full tracebacks.")
@click.option("--quiet", is_flag=True,
              help="Errors only — suppress progress.")
@click.option("--json-logs", is_flag=True,
              help="JSON log lines to stderr (for CI).")
@click.option("--no-file-log", is_flag=True,
              help="Disable file logging.")
@click.option("--triage-all", is_flag=True,
              help="Triage LOW findings too (default: only MEDIUM+).")
@click.option("--trace", is_flag=True,
              help="Write per-agent trace files to var/output/{run}/traces/.")
@click.option("--no-preflight", is_flag=True,
              help="Skip the pre-run provider auth probe and pricing validation (LLM modes).")
@click.option("--fail-on", "fail_on", default=None,
              type=click.Choice(["urgent", "elevated", "moderate", "low"]),
              help="Exit 3 if any finding is at or above this priority band (for CI gating).")
@click.option("--fail-on-degraded", is_flag=True,
              help="Exit 4 if the review completed with coverage gaps (degradations).")
@click.option("--exclude", "exclude", multiple=True,
              help="Glob (relative path) to exclude, repeatable. e.g. --exclude 'third_party/*'")
@click.option("--include", "include", multiple=True,
              help="Restrict review to matching globs, repeatable.")
def review(target, mode, provider, budget, output, summary, report_format, config_path,
           resume, stream, verbose, debug, quiet, json_logs, no_file_log, triage_all,
           trace, no_preflight, fail_on, fail_on_degraded, exclude, include):
    """Run the security review pipeline.

    Exit codes: 0 pass; 1 crash (partial artifacts salvaged when possible);
    2 CLI usage error (click); 3 findings at/above --fail-on; 4 completed
    with coverage gaps and --fail-on-degraded; 130 interrupted (Ctrl-C).
    """
    # --resume reuses the original run's configuration verbatim — combining
    # it with flags that would change that configuration is an error, not a
    # silent mix (fail-loud). Usage errors exit 2 via click.
    if resume:
        conflicting = {
            "--target": target, "--mode": mode, "--provider": provider,
            "--budget": budget, "--output": output, "--summary": summary,
            "--format": report_format, "--config": config_path,
            "--triage-all": triage_all or None,
            "--exclude": (exclude or None), "--include": (include or None),
        }
        given = [name for name, value in conflicting.items() if value is not None]
        if given:
            raise click.UsageError(
                f"--resume reuses the original run's configuration; "
                f"remove conflicting option(s): {', '.join(given)}"
            )
    elif target is None:
        raise click.UsageError("Missing option '--target' (or use --resume <run-dir>).")

    ctx = _setup_logging(verbose, debug, quiet, json_logs, no_file_log)
    show_detail = ctx["verbose"] or ctx["debug"]

    from security_review.logging import get_logger
    logger = get_logger(__name__)

    from security_review.config import load_config
    from security_review.config_schema import SecurityReviewConfig
    from security_review.errors import SecurityReviewError

    work_dir = PROJECT_ROOT
    from security_review import __version__
    from security_review.run_ledger import RunLedger

    if resume:
        # Rebuild everything from the original run's artifacts: run.json for
        # run_id/target/formats, state/config.json for the full config —
        # never parsed from the directory name (fragile with hyphens).
        run_dir = Path(resume).resolve()
        from security_review.passes.checkpoint import load_resume_context
        try:
            run_manifest, cfg = load_resume_context(run_dir)
        except SecurityReviewError as e:
            click.echo(f"Cannot resume {run_dir}: {e}", err=True)
            raise SystemExit(1)
        recorded_out_dir = (work_dir / cfg.review.output_sarif).parent.resolve()
        if recorded_out_dir != run_dir:
            click.echo(
                f"Cannot resume {run_dir}: its config records outputs under "
                f"{recorded_out_dir} — was the run directory moved?", err=True)
            raise SystemExit(1)
        run_id = run_manifest["run_id"]
        target_path = Path(run_manifest["target"])
        if not target_path.exists():
            click.echo(f"Cannot resume: original target no longer exists: {target_path}", err=True)
            raise SystemExit(1)
        mode = cfg.review.mode
        output = cfg.review.output_sarif
        formats = run_manifest.get("formats") or ["summary"]
        out_dir = run_dir
        effective_provider = cfg.llm.provider_model
    else:
        mode = mode or "full"
        report_format = report_format or "summary"

        cfg = load_config(Path(config_path) if config_path else None)

        # Auto-generate dated output directory with run ID for uniqueness
        run_id = uuid4().hex[:8]
        date_str = datetime.now().strftime("%Y-%m-%d")
        target_name = Path(target).resolve().name
        safe_name = "".join(c if c.isalnum() or c in "-." else "-" for c in target_name).strip("-")
        auto_dir = f"var/output/{date_str}-{safe_name}-{run_id}"

        if output is None:
            output = f"{auto_dir}/security-report.sarif"
        if summary is None:
            summary = f"{auto_dir}/security-report.md"
        triage = str(Path(output).parent / "triage.json")

        # Apply CLI overrides via model_validate (enforces constraints)
        overrides: dict = {}
        overrides.setdefault("review", {})["mode"] = mode
        if provider:
            overrides.setdefault("llm", {})["provider_model"] = provider
            overrides.setdefault("llm", {})["triage_model"] = provider
        if budget is not None:
            overrides.setdefault("llm", {})["max_budget_usd"] = budget
        overrides.setdefault("review", {})["output_sarif"] = output
        overrides.setdefault("review", {})["output_summary"] = summary
        overrides.setdefault("review", {})["output_triage"] = triage
        if triage_all:
            overrides.setdefault("triage", {})["min_score"] = 0.0
        if exclude:
            overrides.setdefault("review", {})["exclude"] = list(exclude)
        if include:
            overrides.setdefault("review", {})["include"] = list(include)

        merged = cfg.model_dump()
        for section, values in overrides.items():
            merged.setdefault(section, {}).update(values)

        try:
            cfg = SecurityReviewConfig.model_validate(merged)
        except Exception as e:
            click.echo(f"Invalid option: {e}", err=True)
            raise SystemExit(1)

        target_path = Path(target).resolve()

        # Parse report formats
        if report_format == "all":
            formats = ["summary", "full", "json", "csv"]
        else:
            formats = [f.strip() for f in report_format.split(",")]

        effective_provider = provider or cfg.llm.provider_model

        # Run manifest — written before Pass 1 starts, so it exists even if the
        # pipeline never gets far enough to salvage a report (WP3).
        out_dir = Path(output).parent
        out_dir.mkdir(parents=True, exist_ok=True)
        run_manifest = {
            "run_id": run_id,
            "target": str(target_path),
            "mode": mode,
            "provider": effective_provider,
            "formats": formats,
            "scar_version": __version__,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        (out_dir / "run.json").write_text(json.dumps(run_manifest, indent=2), encoding="utf-8")

    from security_review.passes.pipeline import PipelineState, run_pipeline

    _pipeline_start = _time.monotonic()
    _pass_start = _pipeline_start

    def on_progress(pass_number: int, pass_name: str, status: str, detail: str) -> None:
        nonlocal _pass_start
        if quiet:
            return
        if status == "running":
            _pass_start = _time.monotonic()
            click.echo(click.style(f"  [{pass_number}] ", fg="cyan") + detail, nl=False)
        elif status == "done":
            pass_elapsed = _time.monotonic() - _pass_start
            total_elapsed = _time.monotonic() - _pipeline_start
            click.echo(
                click.style(" done", fg="green")
                + f" — {detail}"
                + click.style(f"  [{int(pass_elapsed)}s / {int(total_elapsed)}s total]", dim=True)
            )
        elif status == "counter":
            click.echo(f"\r      {detail}", nl=False)
        elif status == "tool":
            styled = detail
            if "failed" in detail or "NOT INSTALLED" in detail:
                styled = click.style(detail, fg="red")
            elif "skipped" in detail:
                styled = click.style(detail, dim=True)
            click.echo(f"\n      {styled}", nl=False)
        elif status == "detail" and show_detail:
            click.echo(click.style(f"\n      ", dim=True) + click.style(detail, dim=True), nl=False)

    state = PipelineState(
        config=cfg,
        target_path=target_path,
        work_dir=work_dir,
        run_id=run_id,
        on_progress=on_progress,
        report_formats=formats,
        trace_enabled=trace,
        resume=bool(resume),
        stream_enabled=stream,
        ledger=RunLedger(out_dir / "events.jsonl"),
    )

    if not quiet:
        click.echo(f"\nSCAR — {mode} mode{' (resuming)' if resume else ''}")
        click.echo(f"  Target:   {target_path}")
        click.echo(f"  Provider: {effective_provider}")
        click.echo()

    logger.info("pipeline.starting",
                target=str(target_path), mode=mode,
                provider=effective_provider, resume=bool(resume))

    try:
        if resume:
            # Rehydrate completed passes + spend BEFORE preflight, so a
            # corrupt checkpoint fails fast without burning an LLM probe.
            # Fail-fast: corrupt/invalid state/*.json raises ConfigurationError.
            from security_review.passes.checkpoint import load_into
            restored = load_into(state, out_dir)
            if not quiet and restored:
                click.echo(f"  Resuming run {run_id}: restored "
                           f"{', '.join(sorted(restored))} "
                           f"(spend so far: ${state.cost_tracker.total_spent:.2f})")

        # Preflight also runs on --resume (018 WP4 / plan 020 A.9): cheap, and
        # re-validates auth before resuming spend.
        if mode != "sast" and not no_preflight:
            from security_review.preflight import probe_provider, validate_pricing
            validate_pricing(cfg)
            if not quiet:
                click.echo("  Preflight: probing LLM provider... ", nl=False)
            asyncio.run(probe_provider(cfg, state.cost_tracker))
            if not quiet:
                click.echo(click.style("ok", fg="green"))

        sarif_path = asyncio.run(run_pipeline(state))
        total_elapsed = _time.monotonic() - _pipeline_start
        logger.info("pipeline.complete", sarif=str(sarif_path), pass_failures=len(state.errors))
        minutes, seconds = divmod(int(total_elapsed), 60)
        time_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
        if state.errors:
            click.echo(
                click.style(
                    f"\n  ⚠ Completed in {time_str} with {len(state.errors)} pass(es) failed "
                    "— partial results.",
                    fg="red", bold=True,
                ),
                err=True,
            )
            for e in state.errors:
                click.echo(click.style(f"    - {e.pass_name}: {e.error_type}: {e.error}", fg="red"), err=True)
        if not quiet:
            if not state.errors:
                click.echo(f"\n  Completed in {time_str}")
            click.echo(f"  Report: {sarif_path}")
            from security_review.reporting.dispatcher import FORMAT_FILENAMES
            report_paths = {"Summary": work_dir / cfg.review.output_summary}
            report_paths.update({
                name: sarif_path.parent / FORMAT_FILENAMES[fmt]
                for name, fmt in [("Full", "full"), ("JSON", "json"), ("CSV", "csv")]
            })
            for ext_name, p in report_paths.items():
                if p.exists() and p != sarif_path:
                    click.echo(f"  {ext_name}: {p}")
            # Terminal findings display
            report_data = state.report_data
            if report_data:
                from security_review.reporting.terminal import render_terminal
                render_terminal(report_data)
            # Code quality summary (AST-only, fast)
            try:
                from code_quality import score_project
                quality_result = score_project(
                    target=target_path, tools=[], include_graph=False,
                )
                if report_data:
                    from code_quality.scoring import override_security_from_review
                    override_security_from_review(
                        quality_result,
                        urgent=report_data.urgent,
                        elevated=report_data.elevated,
                        total=report_data.total,
                    )
                from code_quality.display import print_quality_summary
                print_quality_summary(quality_result)
            except Exception as quality_err:
                logger.warning("quality.scoring_failed", error=str(quality_err),
                               error_type=type(quality_err).__name__)
        else:
            click.echo(f"Report: {sarif_path}")
            if state.degradations:
                click.echo(click.style(
                    f"WARNING: {len(state.degradations)} coverage gap(s) — review is incomplete. "
                    f"See 'Coverage Gaps & Failures' in the report.", fg="red"), err=True)

        exit_code = resolve_exit_code(state.report_data, fail_on, fail_on_degraded)
        if exit_code:
            click.echo(click.style(
                f"Exit {exit_code}: " +
                ("findings at or above --fail-on threshold" if exit_code == 3
                 else "review completed with coverage gaps"), fg="red"), err=True)
            raise SystemExit(exit_code)
    except KeyboardInterrupt:
        logger.warning("pipeline.interrupted")
        click.echo("\nInterrupted.", err=True)
        _salvage(state, reason="interrupted by operator (Ctrl-C)")
        raise SystemExit(130)
    except Exception as e:
        logger.error("pipeline.failed", error=str(e), error_type=type(e).__name__)
        if debug:
            import traceback
            traceback.print_exc()
        else:
            click.echo(f"\nFailed: {e}", err=True)
            click.echo("Use --debug for full traceback.", err=True)
        _salvage(state, reason=f"pipeline aborted: {type(e).__name__}: {e}")
        raise SystemExit(1)


def _salvage(state, *, reason: str) -> None:
    """Best-effort write of partial artifacts after an aborted run."""
    from security_review.logging import get_logger
    logger = get_logger(__name__)
    if state.manifest is None:
        return  # nothing ran — nothing to salvage
    from security_review.models.degradation import Degradation
    state.degrade(Degradation(
        pass_name="pipeline", kind="run_aborted", subject="run",
        detail=f"{reason} — artifacts below are PARTIAL",
    ))
    try:
        from security_review.passes.merge import write_artifacts
        path = write_artifacts(state)
        click.echo(click.style(
            f"Partial results salvaged (spend so far: ${state.cost_tracker.total_spent:.2f}): {path.parent}",
            fg="yellow"), err=True)
    except Exception as salvage_err:
        logger.error("salvage.failed", error=str(salvage_err),
                     error_type=type(salvage_err).__name__)
