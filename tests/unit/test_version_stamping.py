"""Tests for version stamping in report footers and the CLI (Plan 018 WP7)."""
from __future__ import annotations

from click.testing import CliRunner

from security_review import __version__
from security_review.cli.app import cli
from security_review.reporting.common import ReportData
from security_review.reporting.full import render_full
from security_review.reporting.summary import render_summary


def test_render_summary_footer_uses_actual_version():
    assert f"SCAR v{__version__}" in render_summary(ReportData())


def test_render_full_footer_uses_actual_version():
    assert f"SCAR v{__version__}" in render_full(ReportData())


def test_cli_version_flag_reports_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
    assert "scar" in result.output.lower()
