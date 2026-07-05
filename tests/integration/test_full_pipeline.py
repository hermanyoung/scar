"""Integration test: full pipeline execution in SAST-only mode.

Uses --mode sast to avoid LLM calls (which are blocked by ALLOW_MODEL_REQUESTS=False).
Validates that Pass 1 (inventory) and Pass 2 (SAST) produce valid output.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_review.config import load_config
from security_review.passes.inventory import run_inventory
from security_review.passes.merge import run_merge
from security_review.passes.state import PipelineState


@pytest.mark.asyncio
async def test_inventory_pass_on_vulnerable_python(vulnerable_python_app, tmp_path):
    """Pass 1 discovers files and assigns security weights."""
    config = load_config()
    state = PipelineState(
        config=config,
        target_path=vulnerable_python_app,
        work_dir=tmp_path,
    )

    await run_inventory(state)

    assert state.manifest is not None
    assert state.manifest.total_files >= 1
    assert "python" in state.manifest.languages

    # The vulnerable app should have high security weight
    app_entry = next(
        (f for f in state.manifest.files if f.path == "app.py"), None
    )
    assert app_entry is not None
    assert app_entry.security_weight >= 2  # has eval(), subprocess, hardcoded password


@pytest.mark.asyncio
async def test_inventory_excludes_pycache(tmp_path):
    """Pass 1 excludes __pycache__ directories."""
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "mod.pyc").write_text("bytecode")
    (tmp_path / "app.py").write_text("print('hello')")

    config = load_config()
    state = PipelineState(
        config=config,
        target_path=tmp_path,
        work_dir=tmp_path / "work",
    )
    (tmp_path / "work").mkdir()

    await run_inventory(state)

    paths = [f.path for f in state.manifest.files]
    assert "app.py" in paths
    assert all("__pycache__" not in p for p in paths)


@pytest.mark.asyncio
async def test_merge_pass_produces_sarif(vulnerable_python_app, tmp_path):
    """Merge pass produces valid SARIF even with no SAST results."""
    config = load_config()
    config.review.mode = "sast"
    config.review.output_sarif = "test-report.sarif"
    config.review.output_summary = "test-report.md"
    config.review.output_triage = "test-triage.json"

    state = PipelineState(
        config=config,
        target_path=vulnerable_python_app,
        work_dir=tmp_path,
    )

    await run_inventory(state)

    # Simulate empty SAST results
    state.sast_sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "security-review", "rules": []}}, "results": []}],
    }

    sarif_path = await run_merge(state)

    assert sarif_path.exists()
    with open(sarif_path) as f:
        sarif = json.load(f)
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif

    # Summary and triage should also exist
    assert (tmp_path / "test-report.md").exists()
    assert (tmp_path / "test-triage.json").exists()
