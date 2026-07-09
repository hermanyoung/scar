"""Tests for the extended health-check command (Plan 018 WP8)."""
from __future__ import annotations

from click.testing import CliRunner

from security_review.cli.app import cli


def test_health_check_shows_configuration_section_and_exits_zero():
    result = CliRunner().invoke(cli, ["health-check"])
    assert result.exit_code == 0, result.output
    assert "Configuration" in result.output
    assert "config/taxonomy/cwe.yaml" in result.output
    assert "pricing:" in result.output


def test_health_check_fails_when_pricing_file_missing(monkeypatch):
    def _raise_missing(model_string):
        from security_review.errors import ConfigurationError
        raise ConfigurationError("Pricing config not found", code="SYS_CONFIG_INVALID")

    monkeypatch.setattr("security_review.budget.pricing_entry_exists", _raise_missing)

    result = CliRunner().invoke(cli, ["health-check"])
    assert result.exit_code == 1
    assert "Problems found" in result.output
