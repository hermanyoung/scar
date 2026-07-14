"""Tests for Pass 6 adversarial verification (Plan 020 Phase 1)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.profiles import ModelProfile

from security_review.budget import CostTracker, ModelPricing
from security_review.config import load_config
from security_review.errors import ConfigurationError
from security_review.models.findings import HolisticFinding, HolisticReviewResult
from security_review.models.config_review import ConfigFinding, ConfigReviewResult
from security_review.models.inventory import FileManifest
from security_review.passes.merge import write_artifacts
from security_review.passes.state import PipelineState
from security_review.passes.verify import (
    _aggregate_votes,
    _build_verify_prompt,
    run_verification,
)
from security_review.run_ledger import RunLedger


# -- Fixtures / helpers --------------------------------------------------------


_APP_SOURCE = (
    "import sqlite3\n"
    "def get_user(name):\n"
    "    conn = sqlite3.connect('app.db')\n"
    "    return conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
)


def _make_state(
    tmp_path: Path,
    *,
    enabled: bool = True,
    samples: int = 1,
    verify_holistic: bool = True,
    verify_config_review: bool = False,
    mode: str = "full",
) -> PipelineState:
    cfg = load_config(None)
    cfg = cfg.model_copy(update={
        "verification": cfg.verification.model_copy(update={
            "enabled": enabled,
            "samples": samples,
            "verify_holistic": verify_holistic,
            "verify_config_review": verify_config_review,
            "model": "openai:test-model",
        }),
        "review": cfg.review.model_copy(update={
            "mode": mode,
            "output_sarif": str(tmp_path / "security-report.sarif"),
            "output_summary": str(tmp_path / "security-report.md"),
            "output_triage": str(tmp_path / "triage.json"),
        }),
    })
    state = PipelineState(config=cfg, target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(files=[], total_files=0, total_tokens=0, languages={})
    state.sast_sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "security-review", "rules": []}}, "results": []}]}
    state.cost_tracker = CostTracker(
        pricing={"openai:test-model": ModelPricing(input_per_token=0.0, output_per_token=0.0)},
    )
    (tmp_path / "app.py").write_text(_APP_SOURCE, encoding="utf-8")
    return state


def _holistic_finding(**overrides) -> HolisticFinding:
    kwargs = dict(
        rule_id="SR-INJ-001",
        title="SQL injection via f-string query",
        description="User input is interpolated into a SQL statement.",
        severity="HIGH",
        file_path="app.py",
        line_number=4,
        cwe_id="CWE-89",
        remediation="Use parameterised queries.",
        evidence="conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
        confidence="high",
    )
    kwargs.update(overrides)
    return HolisticFinding(**kwargs)


def _config_finding(**overrides) -> ConfigFinding:
    kwargs = dict(
        rule_id="SR-CFG-001",
        title="Debug mode enabled",
        description="Debug is on in production settings.",
        severity="MEDIUM",
        file_path="app.py",
        line_number=1,
        cwe_id="CWE-489",
        remediation="Disable debug in production.",
    )
    kwargs.update(overrides)
    return ConfigFinding(**kwargs)


def _prompted_model(respond):
    """FunctionModel with a prompted (non-native-JSON) profile, like copilot/claude."""
    return FunctionModel(respond, profile=ModelProfile(
        supports_json_schema_output=False,
        default_structured_output_mode="prompted",
    ))


def _verdict_response(verdict: str) -> ModelResponse:
    return ModelResponse(parts=[TextPart(
        f"**Verdict:** {verdict}\n**Confidence:** 0.9\n**Rationale:** line 4 shows it."
    )])


def _patch_model(monkeypatch, model) -> None:
    monkeypatch.setattr("security_review.passes.verify.build_model",
                        lambda model_string, llm_config: model)
    monkeypatch.setattr("security_review.passes.verify.build_model_settings",
                        lambda model_string, llm_config: None)


# -- Verdict assignment --------------------------------------------------------


async def test_verify_confirmed_verdict_set_on_holistic_finding(tmp_path, monkeypatch):
    state = _make_state(tmp_path)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])
    _patch_model(monkeypatch, _prompted_model(lambda m, i: _verdict_response("CONFIRMED")))

    await run_verification(state)

    assert finding.triage_verdict == "CONFIRMED"
    assert finding.cwe_id == "CWE-89"  # verification never touches the CWE (019 WP-B)


async def test_verify_false_positive_kept_and_scored_low_after_merge(tmp_path, monkeypatch):
    state = _make_state(tmp_path)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])
    _patch_model(monkeypatch, _prompted_model(lambda m, i: _verdict_response("FALSE_POSITIVE")))

    await run_verification(state)
    assert finding.triage_verdict == "FALSE_POSITIVE"

    sarif_path = write_artifacts(state)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "SR-INJ-001"]
    assert len(results) == 1  # refuted finding is preserved, never dropped
    props = results[0]["properties"]
    assert props["triage_verdict"] == "FALSE_POSITIVE"
    assert props["priority"] == 0.0
    assert props["priority_band"] == "LOW"


async def test_verify_ledger_records_verdicts(tmp_path, monkeypatch):
    state = _make_state(tmp_path)
    state.ledger = RunLedger(tmp_path / "events.jsonl")
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])
    _patch_model(monkeypatch, _prompted_model(lambda m, i: _verdict_response("CONFIRMED")))

    await run_verification(state)

    events = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    verdicts = [e for e in events if e["kind"] == "verify_verdict"]
    assert len(verdicts) == 1
    assert verdicts[0]["rule_id"] == "SR-INJ-001"
    assert verdicts[0]["verdict"] == "CONFIRMED"
    assert "cumulative_usd" in verdicts[0]


# -- Sample aggregation (§1.6) --------------------------------------------------


async def test_verify_samples_majority_refute(tmp_path, monkeypatch):
    state = _make_state(tmp_path, samples=3)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])

    votes = iter(["CONFIRMED", "FALSE_POSITIVE", "FALSE_POSITIVE"])
    _patch_model(monkeypatch, _prompted_model(lambda m, i: _verdict_response(next(votes))))

    await run_verification(state)
    assert finding.triage_verdict == "FALSE_POSITIVE"


async def test_verify_samples_majority_confirm(tmp_path, monkeypatch):
    state = _make_state(tmp_path, samples=3)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])

    votes = iter(["CONFIRMED", "CONFIRMED", "FALSE_POSITIVE"])
    _patch_model(monkeypatch, _prompted_model(lambda m, i: _verdict_response(next(votes))))

    await run_verification(state)
    assert finding.triage_verdict == "CONFIRMED"


def test_aggregate_votes_no_majority_and_no_refute_is_needs_context():
    assert _aggregate_votes(["CONFIRMED", "NEEDS_CONTEXT", "NEEDS_CONTEXT"], 3) == "NEEDS_CONTEXT"


def test_aggregate_votes_failed_samples_count_against_confirmation():
    # 1 CONFIRMED vote of 3 requested samples (2 failed) — no strict majority.
    assert _aggregate_votes(["CONFIRMED"], 3) == "NEEDS_CONTEXT"


# -- Opt-outs --------------------------------------------------------------------


async def test_verify_disabled_is_noop(tmp_path, monkeypatch):
    state = _make_state(tmp_path, enabled=False)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])
    calls = []
    _patch_model(monkeypatch, _prompted_model(lambda m, i: calls.append(1) or _verdict_response("CONFIRMED")))

    await run_verification(state)

    assert finding.triage_verdict is None
    assert calls == []


async def test_verify_config_review_opt_out_leaves_config_findings_untouched(tmp_path, monkeypatch):
    state = _make_state(tmp_path, verify_config_review=False)
    h_finding = _holistic_finding()
    c_finding = _config_finding()
    state.holistic_result = HolisticReviewResult(findings=[h_finding], files_reviewed=["app.py"])
    state.config_review_result = ConfigReviewResult(findings=[c_finding], files_reviewed=["app.py"])
    _patch_model(monkeypatch, _prompted_model(lambda m, i: _verdict_response("CONFIRMED")))

    await run_verification(state)

    assert h_finding.triage_verdict == "CONFIRMED"
    assert c_finding.triage_verdict is None


async def test_verify_config_review_opt_in_verifies_config_findings(tmp_path, monkeypatch):
    state = _make_state(tmp_path, verify_config_review=True)
    c_finding = _config_finding()
    state.config_review_result = ConfigReviewResult(findings=[c_finding], files_reviewed=["app.py"])
    _patch_model(monkeypatch, _prompted_model(lambda m, i: _verdict_response("FALSE_POSITIVE")))

    await run_verification(state)
    assert c_finding.triage_verdict == "FALSE_POSITIVE"


async def test_verify_skipped_outside_full_mode(tmp_path, monkeypatch):
    state = _make_state(tmp_path, mode="sast-triage")
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])
    calls = []
    _patch_model(monkeypatch, _prompted_model(lambda m, i: calls.append(1) or _verdict_response("CONFIRMED")))

    await run_verification(state)

    assert finding.triage_verdict is None
    assert calls == []


# -- Anti-anchoring boundary (design principle 2) --------------------------------


def test_verify_prompt_excludes_finder_reasoning(tmp_path):
    state = _make_state(tmp_path)
    finding = _holistic_finding(
        description="ANCHOR-DESCRIPTION: definitely exploitable, trust me.",
        evidence="ANCHOR-EVIDENCE: conn.execute(...)",
        remediation="ANCHOR-REMEDIATION: use an ORM.",
    )

    prompt = _build_verify_prompt(finding, state)

    assert prompt is not None
    assert "ANCHOR-DESCRIPTION" not in prompt
    assert "ANCHOR-EVIDENCE" not in prompt
    assert "ANCHOR-REMEDIATION" not in prompt
    # The claim itself IS present: CWE, title, location, fresh source.
    assert "CWE-89" in prompt
    assert finding.title in prompt
    assert "app.py" in prompt
    assert "SELECT * FROM users" in prompt  # freshly re-read source


# -- Unresolvable findings (§1.5.2) ----------------------------------------------


async def test_verify_all_samples_failed_sets_needs_context_and_degrades(tmp_path, monkeypatch):
    state = _make_state(tmp_path)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])

    def _boom(messages, info):
        raise RuntimeError("transient transport failure")

    _patch_model(monkeypatch, _prompted_model(_boom))

    await run_verification(state)  # must not raise

    assert finding.triage_verdict == "NEEDS_CONTEXT"  # never None
    check_failed = [d for d in state.degradations
                    if d.pass_name == "verify" and d.kind == "check_failed"]
    assert len(check_failed) == 1
    assert check_failed[0].subject == "SR-INJ-001"
    assert "all_samples_failed" in check_failed[0].detail


async def test_verify_unresolvable_file_path_needs_context_without_llm_call(tmp_path, monkeypatch):
    state = _make_state(tmp_path)
    finding = _holistic_finding(file_path="unknown", line_number=None)
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])
    calls = []
    _patch_model(monkeypatch, _prompted_model(lambda m, i: calls.append(1) or _verdict_response("CONFIRMED")))

    await run_verification(state)

    assert finding.triage_verdict == "NEEDS_CONTEXT"
    assert calls == []
    check_failed = [d for d in state.degradations if d.kind == "check_failed"]
    assert len(check_failed) == 1
    assert "file_unreadable" in check_failed[0].detail


async def test_verify_fatal_sample_error_reraises(tmp_path, monkeypatch):
    state = _make_state(tmp_path)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])

    def _fatal(messages, info):
        raise ConfigurationError("bad provider config", code="SYS_CONFIG_INVALID")

    _patch_model(monkeypatch, _prompted_model(_fatal))

    with pytest.raises(ConfigurationError):
        await run_verification(state)


async def test_verify_budget_exhausted_stamps_remaining_needs_context(tmp_path, monkeypatch):
    state = _make_state(tmp_path)
    findings = [_holistic_finding(), _holistic_finding(rule_id="SR-INJ-002", line_number=2)]
    state.holistic_result = HolisticReviewResult(findings=findings, files_reviewed=["app.py"])

    class _Exhausted(CostTracker):
        def would_exceed_budget(self, max_budget_usd):
            return True

    state.cost_tracker = _Exhausted(pricing={})
    calls = []
    _patch_model(monkeypatch, _prompted_model(lambda m, i: calls.append(1) or _verdict_response("CONFIRMED")))

    await run_verification(state)

    assert calls == []
    assert all(f.triage_verdict == "NEEDS_CONTEXT" for f in findings)
    budget = [d for d in state.degradations
              if d.pass_name == "verify" and d.kind == "budget_exhausted"]
    assert len(budget) == 1
    assert budget[0].subject == "verify"
    assert budget[0].count == 2


# -- Merge guard (§1.5.2 / §1.7) --------------------------------------------------


def test_merge_guard_verdictless_llm_finding_needs_context_when_verification_enabled(tmp_path):
    state = _make_state(tmp_path, enabled=True)
    finding = _holistic_finding()  # triage_verdict stays None
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])

    sarif_path = write_artifacts(state)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "SR-INJ-001")
    assert result["properties"]["triage_verdict"] == "NEEDS_CONTEXT"


def test_merge_guard_verdictless_llm_finding_confirmed_when_verification_disabled(tmp_path):
    state = _make_state(tmp_path, enabled=False)
    finding = _holistic_finding()
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])

    sarif_path = write_artifacts(state)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "SR-INJ-001")
    assert result["properties"]["triage_verdict"] == "CONFIRMED"


def test_merge_carries_explicit_false_positive_verdict(tmp_path):
    state = _make_state(tmp_path, enabled=True)
    finding = _holistic_finding(triage_verdict="FALSE_POSITIVE")
    state.holistic_result = HolisticReviewResult(findings=[finding], files_reviewed=["app.py"])

    sarif_path = write_artifacts(state)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "SR-INJ-001")
    assert result["properties"]["triage_verdict"] == "FALSE_POSITIVE"
    assert result["properties"]["priority_components"]["confidence_label"] == "false_positive"
