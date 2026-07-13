"""Tests for CWE integrity: taxonomy existence helper, deterministic holistic
stamp, merge-boundary drop guard, and the converter taxonomy guard (Plan 019 WP-B).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel

from security_review.budget import CostTracker, ModelPricing
from security_review.checks import CWECheck
from security_review.errors import ConfigurationError
from security_review.models.config_review import ConfigFinding, ConfigReviewResult
from security_review.models.inventory import FileManifest
from security_review.passes.holistic import run_single_check
from security_review.passes.merge import write_artifacts
from security_review.passes.state import PipelineState
from security_review.sarif.converter import convert_pip_audit_to_sarif
from security_review.sarif.taxonomy import cwe_exists


# -- cwe_exists ----------------------------------------------------------------


def test_cwe_exists_with_prefix():
    assert cwe_exists("CWE-89") is True


def test_cwe_exists_bare_number():
    assert cwe_exists("89") is True


def test_cwe_exists_unknown():
    assert cwe_exists("CWE-99999") is False


# -- Deterministic CWE stamp in the holistic pass -------------------------------


async def test_holistic_stamp_overrides_llm_echoed_cwe(tmp_path: Path):
    """A finding claiming CWE-79 inside a CWE-863 check is stamped CWE-863 (P13)."""
    from security_review.config import load_config

    (tmp_path / "controllers").mkdir()
    (tmp_path / "controllers" / "user.py").write_text(
        "def get(id):\n    return db.find(id)\n", encoding="utf-8",
    )

    def _respond(messages, info):
        return ModelResponse(parts=[TextPart(content=(
            "### Finding 1\n"
            "SR-AUTHZ-001: Missing ownership check\n"
            "**Severity:** HIGH\n"
            "**File:** controllers/user.py\n"
            "**CWE:** CWE-79\n"
            "```python\ndb.find(id)\n```\n"
        ))])

    check = CWECheck(
        cwe_id="863", name="Incorrect Authorization", detection="llm",
        file_types=[], check_prompt="Check for IDOR.",
    )
    state = PipelineState(config=load_config(None), target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(files=[], total_files=0, total_tokens=0, languages={})
    state.sast_sarif = {"runs": []}
    state.cost_tracker = CostTracker(
        pricing={"test:model": ModelPricing(input_per_token=0.0, output_per_token=0.0)},
    )

    result = await run_single_check(
        check=check,
        file_paths=["controllers/user.py"],
        state=state,
        model=FunctionModel(_respond),
        model_string="test:model",
    )

    assert result is not None
    findings, _files_reviewed, _parse_failed = result
    assert findings, "the markdown finding should have been parsed"
    assert all(f.cwe_id == "CWE-863" for f in findings)


# -- Merge-boundary guard --------------------------------------------------------


def test_merge_drops_finding_without_cwe_and_records_degradation(
    tmp_path: Path, sast_pipeline_state,
):
    state = sast_pipeline_state
    state.config_review_result = ConfigReviewResult(
        findings=[ConfigFinding(
            rule_id="SR-CFG-001",
            title="Debug mode enabled",
            description="DEBUG=True in production settings",
            severity="HIGH",
            file_path="settings.py",
            cwe_id=None,
            remediation="Disable debug mode",
        )],
        files_reviewed=["settings.py"],
    )

    sarif_path = write_artifacts(state)

    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)
    rule_ids = [r.get("ruleId") for r in sarif["runs"][0].get("results", [])]
    assert "SR-CFG-001" not in rule_ids

    dropped = [d for d in state.degradations if d.kind == "parse_failed"]
    assert len(dropped) == 1
    assert dropped[0].pass_name == "merge"
    assert dropped[0].subject == "cwe_id"
    assert dropped[0].count == 1


# -- Converter taxonomy guard -----------------------------------------------------


def test_converter_raises_when_dependency_cwe_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("security_review.sarif.taxonomy.cwe_exists", lambda cwe_id: False)

    audit_path = tmp_path / "pip-audit.json"
    audit_path.write_text(json.dumps({
        "dependencies": [
            {"name": "requests", "version": "2.19.0",
             "vulns": [{"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"], "description": "x"}]},
        ],
    }), encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        convert_pip_audit_to_sarif(audit_path)
    assert exc_info.value.code == "SYS_CWE_NOT_FOUND"


def test_converter_tags_dependency_cwe_when_present(tmp_path: Path):
    audit_path = tmp_path / "pip-audit.json"
    audit_path.write_text(json.dumps({
        "dependencies": [
            {"name": "requests", "version": "2.19.0",
             "vulns": [{"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"], "description": "x"}]},
        ],
    }), encoding="utf-8")

    sarif = convert_pip_audit_to_sarif(audit_path)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert any("external/cwe/cwe-1395" in r["properties"]["tags"] for r in rules)
