"""CLI command: quality — score codebase quality using PQI."""
from __future__ import annotations

import json
from pathlib import Path

import click

from security_review.cli import _setup_logging, cli


@cli.command("quality")
@click.option("--target", required=True, type=click.Path(exists=True),
              help="Path to codebase root.")
@click.option("--scope", multiple=True, default=None,
              help="Directories/patterns to include (repeatable).")
@click.option("--exclude", multiple=True, default=None,
              help="Patterns to exclude (repeatable).")
@click.option("--language", default=None,
              type=click.Choice(["python", "csharp", "auto"]),
              help="Language (default: auto-detect).")
@click.option("--profile", default="production",
              type=click.Choice(["production", "library", "safety_critical"]),
              help="Weight profile.")
@click.option("--json", "json_output", is_flag=True,
              help="JSON output to stdout.")
@click.option("--recommendations", is_flag=True,
              help="Show improvement recommendations.")
@click.option("--no-tools", is_flag=True,
              help="Skip external tools (AST/tree-sitter only).")
@click.option("--output", "-o", default=None,
              help="Write JSON to file.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def quality(target, scope, exclude, language, profile, json_output,
            recommendations, no_tools, output, verbose, debug):
    """Score codebase quality using the PyQuality Index (PQI)."""
    _setup_logging(verbose, debug, quiet=not verbose and not debug,
                   json_logs=False, no_file_log=True)

    from code_quality import score_project

    result = score_project(
        target=Path(target).resolve(),
        language=language if language and language != "auto" else None,
        scope=list(scope) or None,
        exclude=list(exclude) or None,
        profile=profile,
        tools=[] if no_tools else None,
        include_graph=True,
    )

    if json_output or output:
        data = {
            "composite": result.composite,
            "quality_band": result.quality_band.value,
            "floor_penalty": result.floor_penalty,
            "file_count": result.file_count,
            "line_count": result.line_count,
            "dimensions": {
                name: {
                    "name": dim.name,
                    "score": round(dim.score, 1),
                    "confidence": dim.confidence,
                    "sub_scores": {k: round(v, 1) for k, v in dim.sub_scores.items()},
                    "recommendations": dim.recommendations,
                }
                for name, dim in result.dimensions.items()
            },
        }
        json_str = json.dumps(data, indent=2)
        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(json_str, encoding="utf-8")
            click.echo(f"Written to {output}")
        else:
            click.echo(json_str)
    else:
        from code_quality.display import print_quality_report
        print_quality_report(result, show_recommendations=recommendations)
