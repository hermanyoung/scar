"""Tests for holistic file-path validation + SARIF location integrity (Plan 021 WP-B).

An LLM-echoed file path is validated against the files actually inlined in
the prompt (P13). Unresolvable paths become the "unknown" sentinel and the
SARIF result omits `locations` rather than fabricating one (P3).
"""
from __future__ import annotations

from pathlib import Path

from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.profiles import ModelProfile

from security_review.checks import CWECheck
from security_review.config import load_config
from security_review.models.findings import HolisticFinding, Severity
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.holistic import _resolve_finding_path, run_holistic
from security_review.passes.merge import _finding_to_sarif_result
from security_review.passes.state import PipelineState

# -- _resolve_finding_path truth table ---------------------------------------


def test_resolve_finding_path_exact_match():
    included = ["src/auth/login.py", "src/auth/session.py"]
    assert _resolve_finding_path("src/auth/login.py", included) == "src/auth/login.py"


def test_resolve_finding_path_dot_slash_prefixed():
    included = ["src/auth/login.py"]
    assert _resolve_finding_path("./src/auth/login.py", included) == "src/auth/login.py"


def test_resolve_finding_path_unique_suffix_match():
    included = ["src/auth/login.py"]
    assert _resolve_finding_path("auth/login.py", included) == "src/auth/login.py"


def test_resolve_finding_path_unique_basename_match():
    included = ["src/auth/login.py"]
    assert _resolve_finding_path("login.py", included) == "src/auth/login.py"


def test_resolve_finding_path_ambiguous_basename_returns_unknown():
    included = ["src/auth/login.py", "src/billing/login.py"]
    assert _resolve_finding_path("login.py", included) == "unknown"


def test_resolve_finding_path_absolute_ish_echo_suffix_matches():
    included = ["src/auth/login.py"]
    assert _resolve_finding_path("/repo/src/auth/login.py", included) == "src/auth/login.py"


def test_resolve_finding_path_empty_or_unknown_passthrough():
    included = ["src/auth/login.py"]
    assert _resolve_finding_path("", included) == "unknown"
    assert _resolve_finding_path("unknown", included) == "unknown"


def test_resolve_finding_path_no_match_returns_unknown():
    included = ["src/auth/login.py"]
    assert _resolve_finding_path("does/not/exist.py", included) == "unknown"


# -- Merge: SARIF location handling ------------------------------------------


def _make_finding(*, file_path: str, cwe_id: str = "CWE-862") -> HolisticFinding:
    return HolisticFinding(
        rule_id="SR-AUTHZ-001",
        title="Missing authorization",
        description="Endpoint modifies data without an auth check.",
        severity=Severity.HIGH,
        file_path=file_path,
        cwe_id=cwe_id,
        remediation="Add an authorization decorator.",
        evidence="def delete_all(): ...",
    )


def test_merge_unresolved_path_omits_locations_but_keeps_cwe_tag():
    finding = _make_finding(file_path="unknown")
    result = _finding_to_sarif_result(finding)

    assert "locations" not in result
    assert result["properties"]["location_unresolved"] is True
    assert "external/cwe/cwe-862" in result["properties"]["tags"]


def test_merge_resolvable_finding_unchanged_shape():
    finding = _make_finding(file_path="src/auth/login.py")
    result = _finding_to_sarif_result(finding)

    assert "location_unresolved" not in result.get("properties", {})
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/auth/login.py"
    assert loc["region"]["startLine"] == 1
    assert "external/cwe/cwe-862" in result["properties"]["tags"]


# -- Pipeline-level: an unresolvable finding path degrades ------------------


def _make_check(cwe_id: str = "999") -> CWECheck:
    return CWECheck(
        cwe_id=cwe_id, name="Test Check", detection="llm",
        file_types=[], check_prompt="Check for the test vulnerability.",
    )


async def test_run_holistic_records_location_unresolved_degradation(tmp_path: Path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    def _respond(messages, info):
        text = (
            "### SR-999-001 — Test finding\n"
            "**Severity:** HIGH\n"
            "**File:** not_in_prompt.py\n"
            "**CWE:** CWE-999\n"
            "**Evidence:**\n```\nx = 1\n```\n"
            "**Remediation:** Fix it.\n"
        )
        return ModelResponse(parts=[TextPart(content=text)])

    prompted_model = FunctionModel(_respond, profile=ModelProfile(
        supports_json_schema_output=False,
        default_structured_output_mode="prompted",
    ))
    monkeypatch.setattr(
        "security_review.passes.holistic.load_cwe_checks", lambda: [_make_check()],
    )
    monkeypatch.setattr(
        "security_review.passes.holistic.build_model",
        lambda model_string, llm_config: prompted_model,
    )
    monkeypatch.setattr(
        "security_review.passes.holistic.build_model_settings",
        lambda model_string, llm_config: None,
    )

    state = PipelineState(config=load_config(None), target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(
        files=[FileEntry(path="app.py", language="python", size_bytes=6,
                         security_weight=1, estimated_tokens=5)],
        total_files=1, total_tokens=5, languages={"python": 1},
    )
    state.sast_sarif = {"runs": []}

    await run_holistic(state)

    assert state.holistic_result is not None
    assert len(state.holistic_result.findings) == 1
    assert state.holistic_result.findings[0].file_path == "unknown"

    unresolved = [d for d in state.degradations if d.kind == "location_unresolved"]
    assert len(unresolved) == 1
    assert unresolved[0].count == 1
