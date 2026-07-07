"""Tests for the append-only run ledger (Plan 018 WP3)."""
from __future__ import annotations

import json
from pathlib import Path

from security_review.run_ledger import RunLedger


def test_append_writes_valid_json_lines(tmp_path: Path):
    ledger = RunLedger(tmp_path / "events.jsonl")
    ledger.append("degradation", pass_name="sast", degradation_kind="tool_missing")
    ledger.append("triage_verdict", index=0, verdict="CONFIRMED")

    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["kind"] == "degradation"
    assert first["pass_name"] == "sast"
    assert first["degradation_kind"] == "tool_missing"
    assert "ts" in first

    second = json.loads(lines[1])
    assert second["kind"] == "triage_verdict"
    assert second["index"] == 0


def test_append_creates_parent_directories(tmp_path: Path):
    ledger = RunLedger(tmp_path / "nested" / "dir" / "events.jsonl")
    ledger.append("degradation", subject="x")
    assert (tmp_path / "nested" / "dir" / "events.jsonl").exists()


def test_append_write_failure_logs_warning_and_does_not_raise(tmp_path: Path, monkeypatch):
    ledger = RunLedger(tmp_path / "events.jsonl")

    def _raise_open(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("builtins.open", _raise_open)
    ledger.append("degradation", subject="x")  # must not raise
