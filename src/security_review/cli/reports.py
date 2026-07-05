"""CLI command: reports — list, view, and compare security review reports."""
from __future__ import annotations

import json as json_mod
from pathlib import Path

import click

from security_review.cli.app import PROJECT_ROOT, cli


@cli.command("reports")
@click.option("--target", default=None, help="Filter by target name substring.")
@click.option("--limit", "-n", default=20, help="Max runs to show.")
@click.option("--show", "show_run_id", default=None, help="Show full report for a run ID.")
@click.option("--compare", "compare_ids", nargs=2, default=None, help="Compare two run IDs (e.g. --compare id1 id2).")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def reports(target, limit, show_run_id, compare_ids, verbose, debug):
    """List, view, and compare security review reports."""
    if show_run_id:
        _reports_show(show_run_id)
        return
    if compare_ids:
        _reports_compare(compare_ids[0], compare_ids[1])
        return

    output_dir = PROJECT_ROOT / "var" / "output"
    if not output_dir.exists():
        click.echo("No reports found.")
        return

    runs = sorted(output_dir.iterdir(), reverse=True)
    if target:
        runs = [r for r in runs if target.lower() in r.name.lower()]

    if not runs:
        click.echo(f"No reports found{f' matching {target!r}' if target else ''}.")
        return

    click.echo(f"\n  {'Run ID':<12} {'Date':<12} {'Target':<30} {'Findings':>8}  {'AuthZ':>5}  {'Status'}")
    click.echo(f"  {'─' * 85}")

    for run_dir in runs[:limit]:
        if not run_dir.is_dir():
            continue
        parts = run_dir.name.split("-")
        if len(parts) < 5:
            continue
        run_id = parts[-1]
        date = "-".join(parts[:3])
        target_name = "-".join(parts[3:-1])

        report = run_dir / "security-report.md"
        if report.exists():
            text = report.read_text(encoding="utf-8", errors="replace")
            total = ""
            for line in text.split("\n"):
                if "Total Findings" in line:
                    total = "".join(c for c in line if c.isdigit())
                    break
            # CWE-862 (Missing Authorization) + CWE-863 (Incorrect Authorization) count
            authz = str(text.count("CWE-862") + text.count("CWE-863"))
            status = click.style("complete", fg="green")
        else:
            total = "-"
            authz = "-"
            status = click.style("incomplete", fg="red")

        click.echo(f"  {run_id:<12} {date:<12} {target_name:<30} {total:>8}  {authz:>5}  {status}")

    click.echo()


def _reports_show(run_id: str) -> None:
    output_dir = PROJECT_ROOT / "var" / "output"
    matches = [d for d in output_dir.iterdir() if d.is_dir() and d.name.endswith(f"-{run_id}")]

    if not matches:
        click.echo(f"No run found with ID: {run_id}", err=True)
        raise SystemExit(1)

    run_dir = matches[0]
    report = run_dir / "security-report.md"
    if not report.exists():
        click.echo(f"Run {run_id} has no report (incomplete run).", err=True)
        raise SystemExit(1)

    from rich.console import Console
    from rich.markdown import Markdown

    console = Console()
    md = Markdown(report.read_text(encoding="utf-8"))
    console.print(md)


def _reports_compare(run_a: str, run_b: str) -> None:
    output_dir = PROJECT_ROOT / "var" / "output"

    def find_run(run_id: str) -> Path:
        matches = [d for d in output_dir.iterdir() if d.is_dir() and d.name.endswith(f"-{run_id}")]
        if not matches:
            click.echo(f"No run found with ID: {run_id}", err=True)
            raise SystemExit(1)
        return matches[0]

    def load_findings(run_dir: Path) -> set[tuple[str, str, int]]:
        sarif_path = run_dir / "security-report.sarif"
        if not sarif_path.exists():
            return set()
        with open(sarif_path) as f:
            sarif = json_mod.load(f)
        findings: set[tuple[str, str, int]] = set()
        for run in sarif.get("runs", []):
            for r in run.get("results", []):
                rule = r.get("ruleId", "")
                locs = r.get("locations", [{}])
                fp = ""
                line = 0
                if locs:
                    phys = locs[0].get("physicalLocation", {})
                    fp = phys.get("artifactLocation", {}).get("uri", "")
                    line = phys.get("region", {}).get("startLine", 0)
                findings.add((rule, fp, line))
        return findings

    dir_a = find_run(run_a)
    dir_b = find_run(run_b)
    findings_a = load_findings(dir_a)
    findings_b = load_findings(dir_b)

    only_a = findings_a - findings_b
    only_b = findings_b - findings_a
    common = findings_a & findings_b

    click.echo(f"\n  Comparing {run_a} vs {run_b}")
    click.echo(f"  {'─' * 50}")
    click.echo(f"  Common findings:    {len(common)}")
    click.echo(f"  Only in {run_a}:  {len(only_a)}")
    click.echo(f"  Only in {run_b}:  {len(only_b)}")

    if only_a:
        click.echo(f"\n  Only in {run_a}:")
        for rule, fp, line in sorted(only_a):
            click.echo(f"    {rule:<40} {fp}:{line}")

    if only_b:
        click.echo(f"\n  Only in {run_b}:")
        for rule, fp, line in sorted(only_b):
            click.echo(f"    {rule:<40} {fp}:{line}")

    click.echo()
