"""CSV export renderer — spreadsheet-friendly findings export.

One row per finding, all fields included. Opens directly in Excel/Sheets.
"""
from __future__ import annotations

import csv
import io

from security_review.reporting.common import ReportData

_COLUMNS = [
    "priority", "priority_band", "severity", "file", "line",
    "rule_id", "cwe", "status", "confidence", "confidence_label", "exposure", "message",
]


def render_csv(data: ReportData) -> str:
    """Render findings as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_COLUMNS)

    for f in data.findings:
        writer.writerow([
            f"{f.priority:.3f}",
            f.priority_band,
            f.severity,
            f.file_path,
            f.line,
            f.rule_id,
            f.cwe,
            f.triage_verdict or "untriaged",
            f"{f.confidence:.2f}",
            f.confidence_label,
            f"{f.exposure:.2f}",
            f.message,
        ])

    return output.getvalue()
