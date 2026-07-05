"""Report format dispatcher.

Routes --format to the appropriate renderer. Each format produces a string
that is either written to a file or printed to stdout.

Adding a new format: create a render_X(data) -> str function, register in FORMATS.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from security_review.reporting.common import ReportData


def render_report(data: ReportData, fmt: str) -> str:
    """Render report data in the specified format.

    Args:
        data: Pre-processed report data.
        fmt: Format name (summary, full, json, csv).

    Returns:
        Rendered report as a string.

    Raises:
        ValueError: If format is not registered.
    """
    renderer = FORMATS.get(fmt)
    if renderer is None:
        valid = ", ".join(sorted(FORMATS.keys()))
        raise ValueError(f"Unknown report format '{fmt}'. Valid formats: {valid}")
    return renderer(data)


def write_reports(
    data: ReportData,
    formats: list[str],
    output_dir: Path,
    summary_path: Path | None = None,
) -> list[Path]:
    """Render and write multiple report formats to the output directory.

    Each format writes to its own filename (see FORMAT_FILENAMES) so that
    requesting multiple formats together (e.g. --format all) never has one
    format silently overwrite another's output.

    Args:
        data: Pre-processed report data.
        formats: List of format names to produce.
        output_dir: Directory to write files to (used for "full"/"json"/"csv").
        summary_path: Full path override for the "summary" format only
            (wired to config.review.output_summary / --summary, resolved
            against work_dir by the caller). Other formats always use
            output_dir + their fixed FORMAT_FILENAMES entry.

    Returns:
        List of paths written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for fmt in formats:
        content = render_report(data, fmt)
        if fmt == "summary" and summary_path is not None:
            path = summary_path
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            filename = FORMAT_FILENAMES.get(fmt, f"security-report.{fmt}")
            path = output_dir / filename
        path.write_text(content, encoding="utf-8")
        written.append(path)

    return written


def _render_summary(data: ReportData) -> str:
    from security_review.reporting.summary import render_summary
    return render_summary(data)


def _render_full(data: ReportData) -> str:
    from security_review.reporting.full import render_full
    return render_full(data)


def _render_json(data: ReportData) -> str:
    from security_review.reporting.json_export import render_json
    return render_json(data)


def _render_csv(data: ReportData) -> str:
    from security_review.reporting.csv_export import render_csv
    return render_csv(data)


# Registry: format name -> renderer function
FORMATS: dict[str, Callable[[ReportData], str]] = {
    "summary": _render_summary,
    "full": _render_full,
    "json": _render_json,
    "csv": _render_csv,
}

# Output filename per format. "full" and "summary" both produce Markdown but
# must not share a filename, or writing both (--format all) would have one
# silently clobber the other.
FORMAT_FILENAMES: dict[str, str] = {
    "summary": "security-report.md",
    "full": "security-report-full.md",
    "json": "security-report.json",
    "csv": "security-report.csv",
}

VALID_FORMATS = sorted(FORMATS.keys())
