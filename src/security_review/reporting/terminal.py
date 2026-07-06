"""Rich terminal output for security review findings.

Renders a findings summary panel and a priority-sorted findings table.
This is the terminal display — not a file format. Always runs after
the pipeline unless --quiet.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from security_review.reporting.common import ReportData

_BAND_STYLES = {
    "URGENT": "bold red",
    "ELEVATED": "rgb(255,165,0)",
    "MODERATE": "yellow",
    "LOW": "dim",
}

_SEVERITY_STYLES = {
    "Critical": "bold red",
    "Medium": "yellow",
    "Low": "dim",
}


def render_terminal(data: ReportData, *, console: Console | None = None, max_findings: int = 20) -> None:
    """Print priority-ranked findings summary to terminal."""
    if console is None:
        console = Console()

    _print_pass_failures(console, data)
    if data.degradations:
        _print_degradations(console, data)

    if data.total == 0:
        console.print("\n  [dim]No findings.[/dim]")
        return

    _print_summary_panel(console, data)
    _print_findings_table(console, data, max_findings=max_findings)
    _print_coverage(console, data)


def _print_pass_failures(console: Console, data: ReportData) -> None:
    """Warn the operator that this is a partial report — some passes did not complete."""
    if not data.errors:
        return
    console.print()
    console.print(
        f"  [bold red]⚠ PARTIAL RESULTS — {len(data.errors)} pass(es) failed.[/bold red] "
        "[dim]Findings below reflect only the passes that completed.[/dim]"
    )
    for err in data.errors:
        console.print(f"    [red]- {err}[/red]")


def _print_degradations(console: Console, data: ReportData) -> None:
    body = "\n".join(
        f"[red]•[/red] [{d.pass_name}] {d.kind} — {d.subject}: {d.detail}"
        for d in data.degradations
    )
    console.print()
    console.print(Panel(body, title="⚠ Coverage Gaps & Failures", border_style="red"))


def _print_summary_panel(console: Console, data: ReportData) -> None:
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column("Label", style="bold")
    summary.add_column("Value")
    summary.add_row("Total Findings", str(data.total))

    if data.has_triage:
        summary.add_row("Confirmed", f"[green]{data.triage_confirmed}[/green]")
        summary.add_row("False Positive", f"[dim]{data.triage_false_positive}[/dim]")
        summary.add_row("Needs Context", f"[yellow]{data.triage_needs_context}[/yellow]")

    summary.add_row("", "")

    for band, count in [("URGENT", data.urgent), ("ELEVATED", data.elevated),
                        ("MODERATE", data.moderate), ("LOW", data.low)]:
        if count > 0:
            style = _BAND_STYLES[band]
            summary.add_row(f"[{style}]{band}[/{style}]", f"[{style}]{count}[/{style}]")

    console.print()
    console.print(Panel(summary, title="Findings Summary", border_style="blue", width=50))


def _print_findings_table(console: Console, data: ReportData, *, max_findings: int = 20) -> None:
    # Filter by score — false positives have priority=0, naturally excluded.
    # Show findings with priority >= 0.20 (MODERATE+).
    top = [f for f in data.findings if f.priority >= 0.20]

    if not top:
        if data.has_triage:
            console.print("\n  [green]No actionable findings — all triaged findings resolved.[/green]\n")
        else:
            console.print("\n  [green]No actionable findings.[/green]\n")
        return

    title = "Fix First"
    table = Table(
        title=title,
        title_style="bold",
        expand=True,
        show_lines=True,
        padding=(0, 1),
        title_justify="left",
    )
    table.add_column("Priority", style="bold", no_wrap=True, width=10)
    table.add_column("Score", width=5, justify="right", no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("CWE", width=9, no_wrap=True)
    table.add_column("Status", width=12, no_wrap=True)
    table.add_column("File", style="cyan", no_wrap=True, ratio=2)
    table.add_column("Line", width=5, justify="right", no_wrap=True)
    table.add_column("Finding", ratio=5, overflow="fold")

    _STATUS_DISPLAY = {
        "CONFIRMED": ("[green]Confirmed[/green]"),
        "FALSE_POSITIVE": ("[dim]False Pos[/dim]"),
        "NEEDS_CONTEXT": ("[yellow]Needs Ctx[/yellow]"),
        "": ("[dim]Untriaged[/dim]"),
    }

    for f in top[:max_findings]:
        band_style = _BAND_STYLES.get(f.priority_band, "dim")
        sev_style = _SEVERITY_STYLES.get(f.severity, "dim")
        status = _STATUS_DISPLAY.get(f.triage_verdict, _STATUS_DISPLAY[""])

        table.add_row(
            f"[{band_style}]{f.priority_band}[/{band_style}]",
            f"{f.priority:.2f}",
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.cwe or "--",
            status,
            f.file_path,
            str(f.line),
            f.message,
        )

    console.print()
    console.print(table)
    console.print()


def _print_coverage(console: Console, data: ReportData) -> None:
    """Print coverage section showing detection layers per file type."""
    if data.coverage is None:
        return

    coverage = data.coverage
    if not coverage.by_type:
        return

    console.print("  [bold]Coverage[/bold]")
    console.print(f"  {'─' * 50}")

    for ft, cov in sorted(coverage.by_type.items(), key=lambda x: x[1].coverage_level):
        count = f"({cov.file_count} file{'s' if cov.file_count != 1 else ''})"
        label = f"  {ft:<14} {count:<14} {cov.summary}"
        if cov.coverage_level == "weak":
            console.print(f"  [yellow]{label}[/yellow]")
        elif cov.coverage_level == "none":
            console.print(f"  [red]{label}[/red]")
        else:
            console.print(f"  {label}")

    console.print()
