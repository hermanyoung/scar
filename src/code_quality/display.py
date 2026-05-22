"""Terminal display functions for code quality scores.

Used by the scar.py CLI to render quality results after a review or standalone.
"""
from __future__ import annotations

import click

from code_quality.models import PQIResult


def print_quality_summary(result: PQIResult) -> None:
    """Compact quality breakdown shown at end of a review."""
    band = result.quality_band.value
    click.echo(f"\n  {'─' * 50}")
    click.echo(f"  Code Quality: {result.composite:.0f}/100 [{band}]")
    click.echo(f"  {'─' * 50}")
    for dim in sorted(result.dimensions.values(), key=lambda d: d.score, reverse=True):
        filled = int(dim.score / 100 * 15)
        bar = f"{'#' * filled}{'.' * (15 - filled)}"
        conf = " *" if dim.confidence < 1.0 else ""
        click.echo(f"  {dim.name:<18} {dim.score:>5.1f}  {bar}{conf}")
    click.echo()


def print_quality_report(result: PQIResult, show_recommendations: bool = False) -> None:
    """Full quality report with optional recommendations."""
    band = result.quality_band.value
    composite = result.composite
    width = 40

    click.echo(f"\n{'=' * 60}")
    click.echo("  PyQuality Index (PQI)")
    click.echo(f"{'=' * 60}")

    filled = int(composite / 100 * width)
    bar = f"{'#' * filled}{'.' * (width - filled)}"
    click.echo(f"\n  Composite Score:  {composite:.1f} / 100  [{band}]")
    click.echo(f"  [{bar}] {composite:.1f}%")
    click.echo(f"\n  Files: {result.file_count}    Lines: {result.line_count:,}")
    if result.floor_penalty < 1.0:
        click.echo(f"  Floor penalty: {result.floor_penalty:.3f}")

    click.echo(f"\n{'-' * 60}")
    click.echo(f"  {'Dimension':<20} {'Score':>6}  {'Bar'}")
    click.echo(f"{'-' * 60}")

    for name, dim in sorted(result.dimensions.items(), key=lambda x: x[1].score, reverse=True):
        dim_filled = int(dim.score / 100 * 20)
        dim_bar = f"{'#' * dim_filled}{'.' * (20 - dim_filled)}"
        conf = f" (conf: {dim.confidence:.0%})" if dim.confidence < 1.0 else ""
        click.echo(f"  {dim.name:<20} {dim.score:>5.1f}  {dim_bar}{conf}")

    if show_recommendations:
        click.echo(f"\n{'-' * 60}")
        click.echo("  Recommendations")
        click.echo(f"{'-' * 60}")
        for name, dim in sorted(result.dimensions.items(), key=lambda x: x[1].score):
            if dim.recommendations:
                click.echo(f"\n  [{dim.name}]")
                for rec in dim.recommendations:
                    click.echo(f"    - {rec}")

    click.echo(f"\n{'=' * 60}\n")
