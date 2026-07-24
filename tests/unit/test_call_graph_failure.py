"""Tests for call-graph build failure visibility (Plan 021 WP-C).

A call-graph build failure (e.g. pyan3's internal KeyError on real
codebases) must remain non-fatal — holistic file selection degrades to
keyword-only — but it must now be recorded as a Degradation instead of
being invisible log-only output.
"""
from __future__ import annotations

from pathlib import Path

from security_review.config import load_config
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.pipeline import _build_call_graph_if_available
from security_review.passes.state import PipelineState


def test_call_graph_build_failure_records_degradation(tmp_path: Path, monkeypatch):
    state = PipelineState(config=load_config(None), target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(
        files=[FileEntry(path="app.py", language="python", size_bytes=6,
                         security_weight=1, estimated_tokens=5)],
        total_files=1, total_tokens=5, languages={"python": 1},
    )

    def _raise_analyze(*args, **kwargs):
        raise KeyError("pyan3 internal")

    monkeypatch.setattr("code_analysis.analyze", _raise_analyze)

    graph, pagerank = _build_call_graph_if_available(state)

    assert graph is None
    assert pagerank is None

    failures = [d for d in state.degradations if d.kind == "call_graph_failed"]
    assert len(failures) == 1
    assert failures[0].pass_name == "pipeline"
    assert failures[0].subject == "call_graph"
    assert "KeyError" in failures[0].detail
    assert "pyan3 internal" in failures[0].detail
