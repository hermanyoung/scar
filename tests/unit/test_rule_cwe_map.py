"""Tests for _apply_rule_cwe_map — hadolint rule→CWE tag injection (Plan 019 WP-C)."""
from __future__ import annotations

import pytest

from security_review.errors import ConfigurationError
from security_review.passes.sast import _apply_rule_cwe_map


def _hadolint_sarif_results_only() -> dict:
    """Real hadolint shape: no driver rules array, results carry only ruleId."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "hadolint", "version": "2.14.0"}},
                "results": [
                    {
                        "ruleId": "DL3007",
                        "level": "warning",
                        "message": {"text": "Using latest is prone to errors"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "Dockerfile"},
                            "region": {"startLine": 1},
                        }}],
                    },
                    {
                        "ruleId": "DL3015",
                        "level": "note",
                        "message": {"text": "Avoid additional packages"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "Dockerfile"},
                            "region": {"startLine": 4},
                        }}],
                    },
                ],
            }
        ],
    }


def _hadolint_sarif_with_driver_rules() -> dict:
    """Alternate shape: driver declares a rules array."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "hadolint", "rules": [
                    {"id": "DL3007", "shortDescription": {"text": "latest tag"}},
                    {"id": "DL3015", "shortDescription": {"text": "extra packages"}},
                ]}},
                "results": [
                    {"ruleId": "DL3007", "level": "warning",
                     "message": {"text": "Using latest"}},
                ],
            }
        ],
    }


def test_results_only_shape_tags_results_and_synthesizes_rule():
    sarif = _hadolint_sarif_results_only()
    _apply_rule_cwe_map(sarif, "hadolint")

    run = sarif["runs"][0]
    dl3007 = run["results"][0]
    assert "external/cwe/cwe-829" in dl3007["properties"]["tags"]

    # Driver rule entry synthesized so taxonomy extraction sees the CWE.
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert "DL3007" in rules
    assert "external/cwe/cwe-829" in rules["DL3007"]["properties"]["tags"]


def test_unmapped_rule_untouched():
    sarif = _hadolint_sarif_results_only()
    _apply_rule_cwe_map(sarif, "hadolint")

    run = sarif["runs"][0]
    dl3015 = run["results"][1]
    tags = dl3015.get("properties", {}).get("tags", [])
    assert not any(t.startswith("external/cwe/") for t in tags)
    rules = {r["id"] for r in run["tool"]["driver"].get("rules", [])}
    assert "DL3015" not in rules


def test_driver_rules_shape_tags_rules():
    sarif = _hadolint_sarif_with_driver_rules()
    _apply_rule_cwe_map(sarif, "hadolint")

    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "external/cwe/cwe-829" in rules["DL3007"]["properties"]["tags"]
    dl3015_tags = rules["DL3015"].get("properties", {}).get("tags", [])
    assert not any(t.startswith("external/cwe/") for t in dl3015_tags)
    # No duplicate rule entry synthesized for the already-declared DL3007.
    assert len([r for r in sarif["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "DL3007"]) == 1


def test_apply_is_idempotent_on_tags():
    sarif = _hadolint_sarif_results_only()
    _apply_rule_cwe_map(sarif, "hadolint")
    _apply_rule_cwe_map(sarif, "hadolint")

    dl3007 = sarif["runs"][0]["results"][0]
    assert dl3007["properties"]["tags"].count("external/cwe/cwe-829") == 1


def test_unknown_cwe_in_map_raises(tmp_path, monkeypatch):
    map_dir = tmp_path / "config" / "taxonomy"
    map_dir.mkdir(parents=True)
    (map_dir / "faketool-cwe-map.yaml").write_text(
        'DL9999: "CWE-99999"\n', encoding="utf-8",
    )
    monkeypatch.setattr("security_review.passes.sast.MODULE_ROOT", tmp_path)

    with pytest.raises(ConfigurationError) as exc_info:
        _apply_rule_cwe_map(_hadolint_sarif_results_only(), "faketool")
    assert exc_info.value.code == "SYS_CWE_NOT_FOUND"


def test_missing_map_file_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("security_review.passes.sast.MODULE_ROOT", tmp_path)

    with pytest.raises(ConfigurationError) as exc_info:
        _apply_rule_cwe_map(_hadolint_sarif_results_only(), "no-such-tool")
    assert exc_info.value.code == "SYS_CONFIG_INVALID"
