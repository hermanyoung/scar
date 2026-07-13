"""Tests for pre-merge URI normalization — cross-tool SAST dedup (Plan 019 WP-E).

merge_sarif dedups by (cwe, file, line). Tools emit different URI formats
(file:///abs, /abs, relative) so normalization must happen BEFORE the merge
or identical findings from two tools are double-counted.
"""
from __future__ import annotations

from pathlib import Path

from security_review.config import load_config
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.sast import _normalize_sarif_uris, run_sast
from security_review.passes.state import PipelineState
from security_review.sarif.merger import merge_sarif


def _sarif_doc(tool_name: str, uri: str, level: str) -> dict:
    """Single-run SARIF doc with one CWE-89 finding at src/a.py:10."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "rules": []}},
                "results": [
                    {
                        "ruleId": f"{tool_name}-sqli",
                        "level": level,
                        "message": {"text": "SQL injection"},
                        "properties": {"tags": ["external/cwe/cwe-089"]},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 10},
                        }}],
                    }
                ],
            }
        ],
    }


def test_normalized_docs_merge_to_one_result_highest_severity_wins():
    doc_a = _sarif_doc("tool-a", "file:///repo/src/a.py", "warning")
    doc_b = _sarif_doc("tool-b", "/repo/src/a.py", "error")

    for doc in (doc_a, doc_b):
        _normalize_sarif_uris(doc, "/repo")

    merged = merge_sarif([doc_a, doc_b])

    results = merged["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/a.py"


async def test_run_sast_dedups_across_tools_with_different_uri_formats(
    tmp_path: Path, monkeypatch,
):
    """run_sast normalizes per-tool docs before merging — the same finding
    reported by two tools with different URI formats yields ONE result."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")

    target_root = str(tmp_path.resolve())
    doc_by_tool = {
        "tool-a": _sarif_doc("tool-a", f"file://{target_root}/src/a.py", "warning"),
        "tool-b": _sarif_doc("tool-b", f"{target_root}/src/a.py", "error"),
    }

    from security_review.tools.registry import SecurityToolSpec

    def _fake_spec(name: str) -> SecurityToolSpec:
        return SecurityToolSpec(
            name=name, binary=name, version_cmd=[name, "--version"],
            output_format="sarif", sarif_native=True,
            arg_template=["{binary}", "{target_path}"],
        )

    specs = [_fake_spec("tool-a"), _fake_spec("tool-b")]
    monkeypatch.setattr("security_review.passes.sast.load_tool_specs", lambda: specs)
    monkeypatch.setattr(SecurityToolSpec, "is_available", lambda self: True)

    async def _fake_run_single_tool(spec, target_path, work_dir, suffix="", *, run_id):
        return doc_by_tool[spec.name]

    monkeypatch.setattr("security_review.passes.sast._run_single_tool", _fake_run_single_tool)

    state = PipelineState(config=load_config(None), target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(
        files=[FileEntry(path="src/a.py", language="python", size_bytes=6,
                         security_weight=1, estimated_tokens=2)],
        total_files=1, total_tokens=2, languages={"python": 1},
    )

    await run_sast(state)

    assert state.sast_sarif is not None
    results = [r for run in state.sast_sarif["runs"] for r in run.get("results", [])]
    assert len(results) == 1
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/a.py"
