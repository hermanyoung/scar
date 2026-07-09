"""Tests for the CI exit-code contract (Plan 018 WP5)."""
from __future__ import annotations

from security_review.cli.review import resolve_exit_code
from security_review.models.degradation import Degradation
from security_review.reporting.common import ReportData


def test_no_threshold_returns_zero():
    data = ReportData(urgent=1, elevated=1, moderate=1, low=1)
    assert resolve_exit_code(data, fail_on=None, fail_on_degraded=False) == 0


def test_fail_on_elevated_with_elevated_finding_returns_three():
    data = ReportData(elevated=1)
    assert resolve_exit_code(data, fail_on="elevated", fail_on_degraded=False) == 3


def test_fail_on_elevated_with_only_moderate_returns_zero():
    data = ReportData(moderate=5)
    assert resolve_exit_code(data, fail_on="elevated", fail_on_degraded=False) == 0


def test_fail_on_degraded_with_degradation_returns_four():
    d = Degradation(pass_name="sast", kind="tool_missing", subject="bandit", detail="missing")
    data = ReportData(degradations=[d])
    assert resolve_exit_code(data, fail_on=None, fail_on_degraded=True) == 4


def test_fail_on_degraded_without_degradation_returns_zero():
    data = ReportData()
    assert resolve_exit_code(data, fail_on=None, fail_on_degraded=True) == 0


def test_findings_threshold_wins_over_degraded_when_both_trigger():
    d = Degradation(pass_name="sast", kind="tool_missing", subject="bandit", detail="missing")
    data = ReportData(urgent=1, degradations=[d])
    assert resolve_exit_code(data, fail_on="urgent", fail_on_degraded=True) == 3


def test_none_report_data_returns_zero():
    assert resolve_exit_code(None, fail_on="urgent", fail_on_degraded=True) == 0
