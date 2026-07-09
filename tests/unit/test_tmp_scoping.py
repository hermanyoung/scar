"""Tests for run-scoped tmp dirs and on-disk redaction in Pass 2 (Plan 018 WP7)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_review.models.report import ToolResult
from security_review.passes.sast import _run_single_tool
from security_review.tools.registry import OutputFormat, SecurityToolSpec


def _make_spec(**overrides) -> SecurityToolSpec:
    defaults = dict(
        name="testtool", binary="testtool", version_cmd=["testtool", "--version"],
        output_format=OutputFormat.SARIF, sarif_native=True, arg_template=["{binary}"],
    )
    defaults.update(overrides)
    return SecurityToolSpec(**defaults)


def _sarif_doc(tool_name: str) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool_name, "rules": []}}, "results": []}],
    }


async def test_output_written_under_run_scoped_tmp_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    spec = _make_spec()

    async def _fake_run_tool(spec, target_path, output_path):
        Path(output_path).write_text(json.dumps(_sarif_doc(spec.name)), encoding="utf-8")
        return ToolResult(tool_name=spec.name, exit_code=0, success=True)

    monkeypatch.setattr("security_review.passes.sast.run_tool", _fake_run_tool)

    doc = await _run_single_tool(spec, "some/target", tmp_path, run_id="abc123")

    assert doc is not None
    expected_path = tmp_path / "var" / "tmp" / "abc123" / "testtool.sarif"
    assert expected_path.exists()


async def test_redact_output_rewrites_file_on_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    spec = _make_spec(redact_output=True)

    async def _fake_run_tool(spec, target_path, output_path):
        Path(output_path).write_text(json.dumps(_sarif_doc(spec.name)), encoding="utf-8")
        return ToolResult(tool_name=spec.name, exit_code=0, success=True)

    def _fake_redact(doc):
        doc["redacted_sentinel"] = True
        return doc

    monkeypatch.setattr("security_review.passes.sast.run_tool", _fake_run_tool)
    monkeypatch.setattr("security_review.passes.sast.redact_sarif", _fake_redact)

    doc = await _run_single_tool(spec, "some/target", tmp_path, run_id="abc123")

    assert doc["redacted_sentinel"] is True
    output_path = tmp_path / "var" / "tmp" / "abc123" / "testtool.sarif"
    on_disk = json.loads(output_path.read_text(encoding="utf-8"))
    assert on_disk["redacted_sentinel"] is True


async def test_redact_output_false_leaves_file_unredacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    spec = _make_spec(redact_output=False)

    async def _fake_run_tool(spec, target_path, output_path):
        Path(output_path).write_text(json.dumps(_sarif_doc(spec.name)), encoding="utf-8")
        return ToolResult(tool_name=spec.name, exit_code=0, success=True)

    def _fake_redact(doc):
        doc["redacted_sentinel"] = True
        return doc

    monkeypatch.setattr("security_review.passes.sast.run_tool", _fake_run_tool)
    monkeypatch.setattr("security_review.passes.sast.redact_sarif", _fake_redact)

    await _run_single_tool(spec, "some/target", tmp_path, run_id="abc123")

    output_path = tmp_path / "var" / "tmp" / "abc123" / "testtool.sarif"
    on_disk = json.loads(output_path.read_text(encoding="utf-8"))
    assert "redacted_sentinel" not in on_disk
