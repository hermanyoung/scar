"""Tests for checkpoint/resume + incremental persistence (Plan 020 Phase 2)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_review.budget import CostTracker, ModelPricing
from security_review.config import load_config
from security_review.errors import ConfigurationError
from security_review.models.config_review import ConfigFinding, ConfigReviewResult
from security_review.models.coverage import CoverageReport, FileCoverage
from security_review.models.degradation import Degradation
from security_review.models.findings import (
    HolisticFinding,
    HolisticReviewResult,
    TriagedFinding,
    TriageResult,
)
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.checkpoint import (
    CHECKPOINTED_PASSES,
    completed_passes,
    init_run,
    load_into,
    load_resume_context,
    save_pass,
    state_dir,
)
from security_review.passes.pipeline import run_pipeline
from security_review.passes.state import PipelineState


# -- Helpers ---------------------------------------------------------------------


def _make_state(tmp_path: Path, *, mode: str = "full") -> PipelineState:
    cfg = load_config(None)
    cfg = cfg.model_copy(update={
        "review": cfg.review.model_copy(update={
            "mode": mode,
            "output_sarif": str(tmp_path / "security-report.sarif"),
            "output_summary": str(tmp_path / "security-report.md"),
            "output_triage": str(tmp_path / "triage.json"),
        }),
    })
    return PipelineState(config=cfg, target_path=tmp_path, work_dir=tmp_path)


def _populate_all_slices(state: PipelineState) -> None:
    state.manifest = FileManifest(
        files=[FileEntry(path="app.py", language="python", size_bytes=10,
                         security_weight=5, estimated_tokens=3)],
        total_files=1, total_tokens=3, languages={"python": 1},
    )
    state.coverage = CoverageReport(by_type={
        "python": FileCoverage(file_type="python", file_count=1,
                               deterministic_tools=["bandit"],
                               semantic_passes=["Holistic"]),
    })
    state.sast_sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "bandit", "rules": []}},
                  "results": [{"ruleId": "B307", "level": "warning",
                               "message": {"text": "eval"},
                               "properties": {"triage_verdict": "CONFIRMED"}}]}],
    }
    state.triage_result = TriageResult(
        findings=[TriagedFinding(original_rule_id="B307", original_tool="bandit",
                                 file_path="app.py", line_number=3,
                                 verdict="CONFIRMED", confidence=0.9,
                                 rationale="demonstrably exploitable")],
        total_confirmed=1, total_false_positive=0, total_needs_context=0,
    )
    state.holistic_result = HolisticReviewResult(
        findings=[HolisticFinding(
            rule_id="SR-INJ-001", title="SQL injection", description="f-string SQL",
            severity="HIGH", file_path="app.py", line_number=4, cwe_id="CWE-89",
            remediation="parameterise", evidence="conn.execute(...)",
            triage_verdict="FALSE_POSITIVE",
        )],
        files_reviewed=["app.py"],
    )
    state.config_review_result = ConfigReviewResult(
        findings=[ConfigFinding(
            rule_id="SR-CFG-001", title="Debug on", description="debug=true",
            severity="MEDIUM", file_path="settings.yaml", cwe_id="CWE-489",
            remediation="turn it off",
        )],
        files_reviewed=["settings.yaml"],
    )
    state.cost_tracker = CostTracker(
        pricing={"openai:test-model": ModelPricing(input_per_token=0.001, output_per_token=0.002)},
    )
    state.cost_tracker.record(agent_name="triage", batch_id="triage-000",
                              model_requested="openai:test-model",
                              tokens_in=100, tokens_out=50)
    state.degrade(Degradation(pass_name="sast", kind="tool_missing",
                              subject="trivy", detail="binary missing"))


# -- save_pass / load_into round-trip ---------------------------------------------


def test_checkpoint_round_trip_every_pass_slice(tmp_path: Path):
    state = _make_state(tmp_path)
    _populate_all_slices(state)
    init_run(state)
    for name in CHECKPOINTED_PASSES:
        save_pass(state, name)

    fresh = _make_state(tmp_path)
    fresh.cost_tracker = CostTracker(pricing={})
    restored = load_into(fresh, tmp_path)

    assert restored == set(CHECKPOINTED_PASSES)
    assert fresh.manifest == state.manifest
    assert fresh.coverage == state.coverage
    assert fresh.sast_sarif == state.sast_sarif
    # Triage checkpoint captures the verdict-annotated SARIF.
    assert fresh.sast_sarif["runs"][0]["results"][0]["properties"]["triage_verdict"] == "CONFIRMED"
    assert fresh.triage_result == state.triage_result
    assert fresh.holistic_result == state.holistic_result
    # Verify-pass verdicts survive (verify re-persists holistic/config results).
    assert fresh.holistic_result.findings[0].triage_verdict == "FALSE_POSITIVE"
    assert fresh.config_review_result == state.config_review_result
    # Spend is preserved and keeps guarding the budget.
    assert fresh.cost_tracker.total_spent == pytest.approx(state.cost_tracker.total_spent)
    assert fresh.cost_tracker.total_spent > 0
    # Degradations survive so the resumed run's report matches a fresh run's.
    assert fresh.degradations == state.degradations


def test_completed_passes_reflects_saved_checkpoints(tmp_path: Path):
    state = _make_state(tmp_path)
    _populate_all_slices(state)
    assert completed_passes(tmp_path) == set()

    save_pass(state, "inventory")
    save_pass(state, "sast")

    assert completed_passes(tmp_path) == {"inventory", "sast"}


def test_missing_checkpoint_files_are_not_an_error(tmp_path: Path):
    fresh = _make_state(tmp_path)
    assert load_into(fresh, tmp_path) == set()
    assert fresh.manifest is None


# -- Fail-fast on corruption (rule 11) ---------------------------------------------


def test_corrupt_checkpoint_raises_configuration_error(tmp_path: Path):
    state = _make_state(tmp_path)
    _populate_all_slices(state)
    save_pass(state, "sast")
    (state_dir(tmp_path) / "sast.json").write_text("{not json", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_into(_make_state(tmp_path), tmp_path)
    assert "sast.json" in str(exc_info.value)


def test_schema_invalid_checkpoint_raises_configuration_error(tmp_path: Path):
    (state_dir(tmp_path)).mkdir(parents=True)
    (state_dir(tmp_path) / "triage.json").write_text(
        json.dumps({"triage_result": {"findings": "not-a-list"}}), encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_into(_make_state(tmp_path), tmp_path)
    assert "triage.json" in str(exc_info.value)


def test_corrupt_cost_checkpoint_raises_configuration_error(tmp_path: Path):
    state = _make_state(tmp_path)
    _populate_all_slices(state)
    save_pass(state, "inventory")
    (state_dir(tmp_path) / "cost.json").write_text(
        json.dumps([{"agent": "triage"}]), encoding="utf-8")  # missing required fields

    with pytest.raises(ConfigurationError):
        load_into(_make_state(tmp_path), tmp_path)


# -- CostTracker.restore ------------------------------------------------------------


def test_cost_tracker_restore_preserves_spend_and_budget_guard():
    tracker = CostTracker(pricing={"openai:test-model": ModelPricing(
        input_per_token=0.01, output_per_token=0.01)})
    tracker.record(agent_name="triage", batch_id="b0",
                   model_requested="openai:test-model", tokens_in=100, tokens_out=100)
    entries = tracker.to_audit_log()

    fresh = CostTracker(pricing={})
    fresh.restore(entries)

    assert fresh.total_spent == pytest.approx(tracker.total_spent)
    assert fresh.would_exceed_budget(max_budget_usd=1.0)
    assert not fresh.would_exceed_budget(max_budget_usd=100.0)


# -- init_run / run.json ---------------------------------------------------------------


def test_init_run_extends_existing_run_json_with_outputs(tmp_path: Path):
    state = _make_state(tmp_path)
    (tmp_path / "run.json").write_text(json.dumps({
        "run_id": state.run_id, "target": str(tmp_path), "mode": "full",
        "provider": "copilot:claude-opus", "formats": ["summary"],
    }), encoding="utf-8")

    init_run(state)

    manifest = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    assert manifest["provider"] == "copilot:claude-opus"  # existing keys preserved
    assert manifest["outputs"]["output_sarif"] == state.config.review.output_sarif
    assert (state_dir(tmp_path) / "config.json").exists()


def test_load_resume_context_round_trips_config(tmp_path: Path):
    state = _make_state(tmp_path)
    (tmp_path / "run.json").write_text(json.dumps({
        "run_id": "abc12345", "target": str(tmp_path), "mode": "full",
        "formats": ["summary", "json"],
    }), encoding="utf-8")
    init_run(state)

    manifest, cfg = load_resume_context(tmp_path)

    assert manifest["run_id"] == "abc12345"
    assert manifest["formats"] == ["summary", "json"]
    assert cfg == state.config


def test_load_resume_context_missing_files_raises(tmp_path: Path):
    with pytest.raises(ConfigurationError) as exc_info:
        load_resume_context(tmp_path)
    assert "resumable" in str(exc_info.value)


# -- Pipeline skip/save integration ---------------------------------------------------


async def test_pipeline_saves_checkpoints_after_each_pass(tmp_path: Path, monkeypatch):
    state = _make_state(tmp_path, mode="sast")

    async def _fake_inventory(s):
        s.manifest = FileManifest(files=[], total_files=0, total_tokens=0, languages={})

    async def _fake_sast(s):
        s.sast_sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {
            "name": "security-review", "rules": []}}, "results": []}]}

    monkeypatch.setattr("security_review.passes.inventory.run_inventory", _fake_inventory)
    monkeypatch.setattr("security_review.passes.sast.run_sast", _fake_sast)

    await run_pipeline(state)

    assert (state_dir(tmp_path) / "inventory.json").exists()
    assert (state_dir(tmp_path) / "sast.json").exists()
    assert (state_dir(tmp_path) / "cost.json").exists()
    assert (state_dir(tmp_path) / "config.json").exists()
    assert json.loads((tmp_path / "run.json").read_text())["outputs"]


async def test_pipeline_resume_skips_completed_passes(tmp_path: Path, monkeypatch):
    # Seed checkpoints as if a previous run completed inventory + sast.
    seeded = _make_state(tmp_path, mode="sast")
    seeded.manifest = FileManifest(files=[], total_files=0, total_tokens=0, languages={})
    seeded.sast_sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {
        "name": "security-review", "rules": []}}, "results": []}]}
    save_pass(seeded, "inventory")
    save_pass(seeded, "sast")

    invoked: list[str] = []

    async def _fake_inventory(s):
        invoked.append("inventory")

    async def _fake_sast(s):
        invoked.append("sast")

    monkeypatch.setattr("security_review.passes.inventory.run_inventory", _fake_inventory)
    monkeypatch.setattr("security_review.passes.sast.run_sast", _fake_sast)

    progress_events: list[tuple[int, str, str, str]] = []
    state = _make_state(tmp_path, mode="sast")
    state.resume = True
    load_into(state, tmp_path)
    state.on_progress = lambda n, name, status, detail: progress_events.append(
        (n, name, status, detail))

    sarif_path = await run_pipeline(state)

    assert invoked == []  # neither pass re-ran
    assert (1, "inventory", "done", "restored from checkpoint") in progress_events
    assert (2, "sast", "done", "restored from checkpoint") in progress_events
    assert sarif_path.exists()  # merge still produced the report


# -- Streaming (§2.2) --------------------------------------------------------------------


def test_write_partial_sarif_includes_llm_findings_without_mutating_state(tmp_path: Path):
    from security_review.passes.merge import write_partial_sarif

    state = _make_state(tmp_path)
    _populate_all_slices(state)
    sast_results_before = json.dumps(state.sast_sarif)

    path = write_partial_sarif(state)

    assert path.name == "security-report.partial.sarif"
    partial = json.loads(path.read_text(encoding="utf-8"))
    rule_ids = {r["ruleId"] for run in partial["runs"] for r in run["results"]}
    assert "SR-INJ-001" in rule_ids
    assert "SR-CFG-001" in rule_ids
    # The verify verdict flows into the partial report's scoring too.
    sr = next(r for r in partial["runs"][0]["results"] if r["ruleId"] == "SR-INJ-001")
    assert sr["properties"]["triage_verdict"] == "FALSE_POSITIVE"
    # Live state untouched — repeated streaming calls never accumulate.
    assert json.dumps(state.sast_sarif) == sast_results_before


def test_write_partial_sarif_repeated_calls_are_idempotent(tmp_path: Path):
    from security_review.passes.merge import write_partial_sarif

    state = _make_state(tmp_path)
    _populate_all_slices(state)

    first = json.loads(write_partial_sarif(state).read_text(encoding="utf-8"))
    second = json.loads(write_partial_sarif(state).read_text(encoding="utf-8"))

    assert first == second


# -- CLI flag validation --------------------------------------------------------------------


def test_cli_resume_conflicts_with_provider_flag(tmp_path: Path):
    from click.testing import CliRunner
    from security_review.cli.review import review

    result = CliRunner().invoke(review, [
        "--resume", str(tmp_path), "--provider", "openai:gpt-5.5",
    ])
    assert result.exit_code == 2
    assert "--provider" in result.output


def test_cli_requires_target_or_resume():
    from click.testing import CliRunner
    from security_review.cli.review import review

    result = CliRunner().invoke(review, [])
    assert result.exit_code == 2
    assert "--target" in result.output


def test_cli_resume_rejects_unresumable_directory(tmp_path: Path):
    from click.testing import CliRunner
    from security_review.cli.review import review

    result = CliRunner().invoke(review, ["--resume", str(tmp_path)])
    assert result.exit_code == 1
    assert "Cannot resume" in result.output
