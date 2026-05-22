"""Tests for SARIF loader: parsing, validation, finding extraction."""
from __future__ import annotations

import json

import pytest

from security_review.errors import SARIFError
from security_review.sarif.loader import (
    extract_findings,
    get_finding_key,
    load_sarif,
    load_sarif_from_string,
)


def test_load_sarif_valid(tmp_path, sample_sarif):
    sarif_file = tmp_path / "test.sarif"
    sarif_file.write_text(json.dumps(sample_sarif), encoding="utf-8")

    result = load_sarif(sarif_file)
    assert result["version"] == "2.1.0"
    assert len(result["runs"]) == 2


def test_load_sarif_missing_file(tmp_path):
    with pytest.raises(SARIFError, match="not found"):
        load_sarif(tmp_path / "missing.sarif")


def test_load_sarif_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.sarif"
    bad_file.write_text("not json", encoding="utf-8")

    with pytest.raises(SARIFError, match="Failed to parse"):
        load_sarif(bad_file)


def test_load_sarif_wrong_version(tmp_path):
    bad_sarif = {"version": "1.0.0", "runs": []}
    sarif_file = tmp_path / "old.sarif"
    sarif_file.write_text(json.dumps(bad_sarif), encoding="utf-8")

    with pytest.raises(SARIFError, match="version"):
        load_sarif(sarif_file)


def test_load_sarif_missing_runs(tmp_path):
    bad_sarif = {"version": "2.1.0"}
    sarif_file = tmp_path / "noruns.sarif"
    sarif_file.write_text(json.dumps(bad_sarif), encoding="utf-8")

    with pytest.raises(SARIFError, match="runs"):
        load_sarif(sarif_file)


def test_load_sarif_from_string(sample_sarif):
    result = load_sarif_from_string(json.dumps(sample_sarif))
    assert result["version"] == "2.1.0"


def test_extract_findings(sample_sarif):
    findings = extract_findings(sample_sarif)
    assert len(findings) == 3
    tools = {f["properties"]["tool_name"] for f in findings}
    assert tools == {"bandit", "gitleaks"}


def test_get_finding_key(sample_sarif):
    findings = extract_findings(sample_sarif)
    key = get_finding_key(findings[0])
    assert key[1] == "app.py"  # file_path
    assert key[2] == 8  # line_number
