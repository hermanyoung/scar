"""Reporting module: render security findings to terminal, markdown, JSON, CSV.

Architecture (follows genos-trading scanner output pattern):
    common.py       — ReportData model, extract_report_data()
    dispatcher.py   — Routes --format to the right renderer
    terminal.py     — Rich console output (always runs, not a file format)
    summary.py      — One-page markdown summary
    full.py         — Complete markdown with every finding grouped by priority
    json_export.py  — Machine-readable JSON for CI/dashboards
    csv_export.py   — Spreadsheet-friendly CSV export

Adding a new format: create a render_X(data) -> str function, register in
dispatcher.FORMATS.

Usage:
    from security_review.reporting.common import extract_report_data
    from security_review.reporting.dispatcher import write_reports
    from security_review.reporting.terminal import render_terminal

    data = extract_report_data(sarif_results, run_id=..., target=..., ...)
    write_reports(data, formats=["summary", "json"], output_dir=path)
    render_terminal(data)
"""
