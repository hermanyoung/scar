"""Tests for write_artifacts as a standalone salvage entry point (Plan 018 WP3)."""
from __future__ import annotations

import json
from pathlib import Path

from security_review import __version__
from security_review.config import load_config
from security_review.models.degradation import Degradation
from security_review.passes.merge import write_artifacts
from security_review.passes.state import PipelineState


def test_write_artifacts_produces_all_files_from_partial_state(tmp_path: Path, sample_sarif: dict):
    cfg = load_config(None)
    review = cfg.review.model_dump()
    review.update({
        "output_sarif": str(tmp_path / "security-report.sarif"),
        "output_summary": str(tmp_path / "security-report.md"),
        "output_triage": str(tmp_path / "triage.json"),
        "mode": "sast",
    })
    cfg = cfg.model_copy(update={"review": cfg.review.__class__.model_validate(review)})

    state = PipelineState(config=cfg, target_path=tmp_path, work_dir=tmp_path)
    state.manifest = None  # a real aborted run may not even reach Pass 1's output
    state.sast_sarif = sample_sarif
    state.degrade(Degradation(
        pass_name="pipeline", kind="run_aborted", subject="run",
        detail="interrupted by operator (Ctrl-C) — artifacts below are PARTIAL",
    ))

    path = write_artifacts(state)

    assert path.exists()
    assert (tmp_path / "security-report.md").exists()
    assert (tmp_path / "triage.json").exists()

    triage_data = json.loads((tmp_path / "triage.json").read_text(encoding="utf-8"))
    assert triage_data["scar_version"] == __version__
    assert any(d["kind"] == "run_aborted" for d in triage_data["degradations"])
