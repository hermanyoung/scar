"""Tests for the list-models command.

Assertions are driven off config/models.yaml and config/pricing.yaml rather
than literal model names, so adding or renaming a model does not break them —
only a change in the command's contract should.
"""
from __future__ import annotations

import json

from click.testing import CliRunner

from security_review.cli import cli


def _providers() -> list[str]:
    from security_review.providers import _load_model_registry
    return sorted(_load_model_registry().get("providers") or {})


def test_list_models_lists_every_configured_provider():
    result = CliRunner().invoke(cli, ["list-models"])
    assert result.exit_code == 0, result.output
    for provider in _providers():
        assert provider in result.output
    assert "usable model(s)" in result.output


def test_list_models_rejects_unknown_provider_without_traceback():
    result = CliRunner().invoke(cli, ["list-models", "--provider", "not-a-provider"])
    assert result.exit_code == 1
    assert "Unknown provider 'not-a-provider'" in result.output
    assert "Traceback" not in result.output
    for provider in _providers():
        assert provider in result.output


def test_list_models_default_view_only_shows_priced_models():
    """Unpriced models are hidden by default: CostTracker.record() would reject them."""
    result = CliRunner().invoke(cli, ["list-models", "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert rows
    assert all(r["input_per_token"] is not None for r in rows)
    assert all(r["output_per_token"] is not None for r in rows)


def test_list_models_all_flag_includes_unpriced_models():
    runner = CliRunner()
    default_rows = json.loads(runner.invoke(cli, ["list-models", "--json"]).output)
    all_rows = json.loads(runner.invoke(cli, ["list-models", "--all", "--json"]).output)

    assert len(all_rows) > len(default_rows)
    assert any(r["input_per_token"] is None for r in all_rows)


def test_list_models_keys_match_the_pricing_lookup_the_pipeline_uses():
    """Every priced row must resolve exactly as CostTracker.record() would.

    This is the invariant that makes the listing trustworthy: if resolution
    here ever diverges from _resolve_pricing_key(), the command would advertise
    models the pipeline cannot bill.
    """
    from security_review.budget import _resolve_pricing_key, pricing_entry_exists

    rows = json.loads(CliRunner().invoke(cli, ["list-models", "--all", "--json"]).output)
    for row in rows:
        selector = f"{row['provider']}:{row['alias'] or row['wire_id']}"
        assert _resolve_pricing_key(selector) == row["key"]
        assert pricing_entry_exists(selector) is (row["input_per_token"] is not None)


def _fake_az(deployments: list[dict], models: list[dict]):
    """Stand in for run_tool_sync, dispatching on which az query was issued."""
    import subprocess

    def _run(cmd, timeout_seconds, cwd=None):
        payload = models if "model" in cmd else deployments
        return subprocess.CompletedProcess(
            cmd, returncode=0, stdout=json.dumps(payload), stderr="",
        )
    return _run


_DEPLOYMENT = {
    "name": "gpt-5.4",
    "sku": {"name": "DataZoneStandard", "capacity": 250},
    "properties": {
        "model": {"name": "gpt-5.4", "version": "2026-03-05", "format": "OpenAI"},
        "provisioningState": "Succeeded",
    },
}

_CATALOG_MODEL = {
    "kind": "AIServices",
    "model": {
        "name": "claude-opus-5", "version": "2", "format": "Anthropic",
        "lifecycleStatus": "GenerallyAvailable", "isDefaultVersion": True,
        "skus": [{"name": "GlobalStandard"}],
        "capabilities": {"hostedOn": "azure", "chatCompletion": "true"},
        "deprecation": {"inference": "2027-07-08T00:00:00Z"},
    },
}


def test_foundry_lists_published_deployments(monkeypatch):
    monkeypatch.setattr("security_review.tools.runner.run_tool_sync",
                        _fake_az([_DEPLOYMENT], []))
    result = CliRunner().invoke(cli, ["list-models", "--foundry"])
    assert result.exit_code == 0, result.output
    assert "Published — callable now" in result.output
    assert "gpt-5.4" in result.output
    # gpt-5.4 carries a foundry: pricing entry, so it counts as routable.
    assert "1 published, 1 priced" in result.output


def test_foundry_marks_unpriced_deployments_as_unroutable(monkeypatch):
    """A deployment SCAR cannot bill must be visibly distinguished, not omitted."""
    unpriced = {
        "name": "model-router",
        "sku": {"name": "DataZoneStandard", "capacity": 250},
        "properties": {
            "model": {"name": "model-router", "version": "2025-11-18", "format": "OpenAI"},
            "provisioningState": "Succeeded",
        },
    }
    monkeypatch.setattr("security_review.tools.runner.run_tool_sync",
                        _fake_az([_DEPLOYMENT, unpriced], []))
    result = CliRunner().invoke(cli, ["list-models", "--foundry"])
    assert result.exit_code == 0, result.output
    assert "2 published, 1 priced" in result.output
    assert "add a 'foundry:<model>' entry" in result.output


def test_foundry_catalog_dedupes_repeated_account_kinds(monkeypatch):
    """Azure repeats each model per account kind; the same pair must appear once."""
    maas = {**_CATALOG_MODEL, "kind": "MaaS"}
    monkeypatch.setattr("security_review.tools.runner.run_tool_sync",
                        _fake_az([], [_CATALOG_MODEL, maas]))

    result = CliRunner().invoke(cli, ["list-models", "--foundry", "--catalog", "--json"])
    assert result.exit_code == 0, result.output
    catalog = json.loads(result.output)["catalog"]
    assert len(catalog) == 1
    assert catalog[0]["hosted_on"] == "azure"
    assert catalog[0]["is_default_version"] is True
    assert catalog[0]["inference_retires"].startswith("2027-07-08")


def test_foundry_publisher_filter_is_applied(monkeypatch):
    openai_model = {
        "kind": "AIServices",
        "model": {"name": "gpt-5.4", "version": "1", "format": "OpenAI",
                  "lifecycleStatus": "GenerallyAvailable", "skus": []},
    }
    monkeypatch.setattr("security_review.tools.runner.run_tool_sync",
                        _fake_az([], [_CATALOG_MODEL, openai_model]))

    result = CliRunner().invoke(
        cli, ["list-models", "--foundry", "--catalog", "--publisher", "anthropic", "--json"])
    assert result.exit_code == 0, result.output
    catalog = json.loads(result.output)["catalog"]
    assert [e["model_name"] for e in catalog] == ["claude-opus-5"]


def test_foundry_surfaces_az_failure_instead_of_reporting_no_models(monkeypatch):
    """A failed az call must never look like an empty resource."""
    import subprocess

    def _fail(cmd, timeout_seconds, cwd=None):
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr="az: command not found")

    monkeypatch.setattr("security_review.tools.runner.run_tool_sync", _fail)
    result = CliRunner().invoke(cli, ["list-models", "--foundry"])
    assert result.exit_code == 1
    assert "az query failed" in result.output
    assert "az: command not found" in result.output
    assert "none deployed" not in result.output


def test_foundry_requires_the_config_block(monkeypatch):
    from security_review.config import load_config

    def _without_foundry(path=None):
        cfg = load_config(path)
        return cfg.model_copy(update={"foundry": None})

    monkeypatch.setattr("security_review.config.load_config", _without_foundry)
    result = CliRunner().invoke(cli, ["list-models", "--foundry"])
    assert result.exit_code == 1
    assert "No `foundry:` block" in result.output


def test_registry_flags_and_foundry_flags_are_mutually_exclusive():
    runner = CliRunner()
    both = runner.invoke(cli, ["list-models", "--foundry", "--provider", "openai"])
    assert both.exit_code == 1
    assert "cannot be combined" in both.output

    orphan = runner.invoke(cli, ["list-models", "--catalog"])
    assert orphan.exit_code == 1
    assert "only apply with --foundry" in orphan.output


def test_list_models_filter_restricts_output_to_one_provider():
    provider = _providers()[0]
    result = CliRunner().invoke(cli, ["list-models", "--provider", provider, "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert rows
    assert {r["provider"] for r in rows} == {provider}
