"""Tests for cross-run finding tracking wired into the merge pass."""

from __future__ import annotations

from pathlib import Path

from code_analysis.store import GraphStore
from security_review.passes.merge import fingerprint_and_track_findings


SAMPLE_RESULTS = [
    {
        "ruleId": "opengrep.cwe-89.sql-injection",
        "level": "error",
        "message": {"text": "SQL injection via string formatting"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app.py"}, "region": {"startLine": 12},
        }}],
    },
]
RULE_CWE_MAP = {"opengrep.cwe-89.sql-injection": "CWE-89"}


def test_records_new_finding_on_first_run(sast_pipeline_state, tmp_path: Path):
    state = sast_pipeline_state
    fingerprint_and_track_findings(state, SAMPLE_RESULTS, RULE_CWE_MAP)

    with GraphStore(tmp_path / ".scar" / "graph.db") as store:
        row = store._conn.execute(
            "SELECT status, cwe_id, file_path FROM findings WHERE run_id=?", (state.run_id,),
        ).fetchone()
    assert row == ("open", "CWE-89", "app.py")


def test_second_run_same_finding_is_recurring(sast_pipeline_state, tmp_path: Path):
    state = sast_pipeline_state
    fingerprint_and_track_findings(state, SAMPLE_RESULTS, RULE_CWE_MAP)

    state.run_id = "second-run-id"
    fingerprint_and_track_findings(state, SAMPLE_RESULTS, RULE_CWE_MAP)

    with GraphStore(tmp_path / ".scar" / "graph.db") as store:
        first_seen = store._conn.execute(
            "SELECT first_seen_run FROM findings WHERE run_id=?", ("second-run-id",),
        ).fetchone()[0]
    assert first_seen != "second-run-id"  # carried forward from the first run


def test_never_raises_when_target_path_unwritable(sast_pipeline_state, monkeypatch):
    state = sast_pipeline_state

    def _boom(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr("code_analysis.store.init_target_gitignore", _boom)

    fingerprint_and_track_findings(state, SAMPLE_RESULTS, RULE_CWE_MAP)  # must not raise
