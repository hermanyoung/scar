"""Sensitive environment files are scanned deterministically, never by an LLM."""
from __future__ import annotations

from pathlib import Path

import pytest

from security_review.config import load_config
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.config_review import run_config_review
from security_review.passes.state import PipelineState


@pytest.mark.asyncio
async def test_config_review_omits_sensitive_env_and_records_degradation(
    tmp_path: Path,
):
    env_path = tmp_path / "config" / ".env"
    env_path.parent.mkdir()
    env_path.write_text("API_KEY=must-not-enter-a-prompt", encoding="utf-8")

    config = load_config(None)
    state = PipelineState(config=config, target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(
        files=[
            FileEntry(
                path="config/.env",
                language="config",
                size_bytes=env_path.stat().st_size,
                security_weight=10,
                estimated_tokens=10,
            ),
        ],
        total_files=1,
        total_tokens=10,
        languages={"config": 1},
    )

    await run_config_review(state)

    omitted = [
        d for d in state.degradations
        if d.kind == "sensitive_file_omitted"
    ]
    assert len(omitted) == 1
    assert omitted[0].count == 1
    assert "config/.env" in omitted[0].detail
    assert state.config_review_result is None
