"""Tests for tool_missing/no_tools degradation recording in Pass 2 (Plan 018 WP1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from security_review.config import load_config
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.sast import run_sast
from security_review.passes.state import PipelineState
from security_review.tools.registry import SecurityToolSpec


def _build_state(tmp_path: Path) -> PipelineState:
    cfg = load_config(None)
    manifest = FileManifest(
        files=[FileEntry(path="app.py", language="python", size_bytes=10,
                          security_weight=1, estimated_tokens=5)],
        total_files=1, total_tokens=5, languages={"python": 1},
    )
    state = PipelineState(config=cfg, target_path=tmp_path, work_dir=tmp_path)
    state.manifest = manifest
    return state


async def test_all_tools_missing_records_degradation_per_tool_and_no_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(SecurityToolSpec, "is_available", lambda self: False)

    state = _build_state(tmp_path)
    await run_sast(state)

    kinds = [(d.kind, d.subject) for d in state.degradations]
    tool_missing = [k for k in kinds if k[0] == "tool_missing"]
    # One per applicable-but-unavailable tool, plus the aggregate "no_tools" one.
    assert ("tool_missing", "sast") in tool_missing
    assert len(tool_missing) > 1
    assert state.sast_sarif is not None
