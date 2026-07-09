"""Tests for reports listing guards, salvaged status, and pruning (Plan 018 WP10)."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from security_review.cli.app import cli

_SAMPLE_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "scar", "rules": []}}, "results": []}],
}


def _make_runs(tmp_path: Path) -> Path:
    output_dir = tmp_path / "var" / "output"
    output_dir.mkdir(parents=True)

    complete = output_dir / "2026-07-05-testapp-aaaa1111"
    complete.mkdir()
    (complete / "security-report.md").write_text("**Total Findings:** 0\n", encoding="utf-8")
    (complete / "security-report.sarif").write_text(json.dumps(_SAMPLE_SARIF), encoding="utf-8")

    salvaged = output_dir / "2026-07-05-testapp-bbbb2222"
    salvaged.mkdir()
    (salvaged / "security-report.md").write_text("**Total Findings:** 0\n", encoding="utf-8")
    (salvaged / "triage.json").write_text(json.dumps({
        "degradations": [{"pass_name": "pipeline", "kind": "run_aborted",
                          "subject": "run", "detail": "interrupted", "count": 0}],
    }), encoding="utf-8")

    incomplete = output_dir / "2026-07-05-testapp-cccc3333"
    incomplete.mkdir()

    return output_dir


def test_listing_shows_complete_salvaged_incomplete(tmp_path: Path, monkeypatch):
    _make_runs(tmp_path)
    monkeypatch.setattr("security_review.cli.reports.PROJECT_ROOT", tmp_path)

    result = CliRunner().invoke(cli, ["reports"])
    assert result.exit_code == 0, result.output
    assert "aaaa1111" in result.output and "complete" in result.output
    assert "bbbb2222" in result.output and "salvaged" in result.output
    assert "cccc3333" in result.output and "incomplete" in result.output


def test_compare_against_incomplete_run_exits_one(tmp_path: Path, monkeypatch):
    _make_runs(tmp_path)
    monkeypatch.setattr("security_review.cli.reports.PROJECT_ROOT", tmp_path)

    result = CliRunner().invoke(cli, ["reports", "--compare", "aaaa1111", "cccc3333"])
    assert result.exit_code == 1
    assert "incomplete run" in result.output.lower() or "incomplete run" in str(result.exception)


def test_prune_incomplete_removes_only_empty_dir(tmp_path: Path, monkeypatch):
    output_dir = _make_runs(tmp_path)
    monkeypatch.setattr("security_review.cli.reports.PROJECT_ROOT", tmp_path)

    result = CliRunner().invoke(cli, ["reports", "--prune-incomplete", "--yes"])
    assert result.exit_code == 0, result.output

    remaining = {d.name for d in output_dir.iterdir()}
    assert remaining == {"2026-07-05-testapp-aaaa1111", "2026-07-05-testapp-bbbb2222"}
