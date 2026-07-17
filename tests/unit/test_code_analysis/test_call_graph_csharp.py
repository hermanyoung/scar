"""Tests for C# call graph extraction (Roslyn tool integration).

Mocks security_review.tools.runner.run_tool_sync -- these tests never invoke
dotnet or the real Roslyn tool (that was verified manually against a live
.csproj fixture during development; see plan 010 notes).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from code_analysis.call_graph_csharp import build_csharp_call_edges


FIXTURE_EDGES = [
    {"caller": "App.Controllers.UserController.CreateUser", "callee": "App.Services.UserService.Save",
     "file": "UserController.cs", "line": 11, "isVirtual": False, "isExtension": False},
    {"caller": "App.Extensions.Caller.Run", "callee": "System.String.IsSafe",
     "file": "Extensions.cs", "line": 22, "isVirtual": False, "isExtension": True},
    {"caller": "App.Extensions.Caller.Run", "callee": "App.Extensions.Base.Greet",
     "file": "Extensions.cs", "line": 23, "isVirtual": True, "isExtension": False},
]


def _mock_success_run_tool_sync(output_path: Path, edges: list[dict]):
    def _run(cmd, timeout_seconds, cwd=None):
        output_path.write_text(json.dumps(edges), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
    return _run


@pytest.fixture
def fake_tool_present(monkeypatch, tmp_path):
    """Pretend the Roslyn tool binary exists, without needing a real build."""
    monkeypatch.setattr(
        "code_analysis.call_graph_csharp._find_roslyn_tool",
        lambda: tmp_path / "fake-roslyn-callgraph.dll",
    )
    return tmp_path


class TestBuildCsharpCallEdges:
    def test_tool_not_found_returns_empty_list(self, monkeypatch, tmp_path):
        monkeypatch.setattr("code_analysis.call_graph_csharp._find_roslyn_tool", lambda: None)
        edges = build_csharp_call_edges(tmp_path, tmp_path / "App.csproj")
        assert edges == []

    def test_parses_edges_with_correct_confidence_and_kind(self, fake_tool_present, monkeypatch):
        root = fake_tool_present
        output_path = root / ".scar" / "roslyn-callgraph.json"
        monkeypatch.setattr(
            "security_review.tools.runner.run_tool_sync",
            _mock_success_run_tool_sync(output_path, FIXTURE_EDGES),
        )

        edges = build_csharp_call_edges(root, root / "App.csproj")
        by_callee = {e.callee: e for e in edges}

        direct = by_callee["App.Services.UserService.Save"]
        assert direct.confidence == 0.9
        assert direct.kind == "direct"

        extension = by_callee["System.String.IsSafe"]
        assert extension.kind == "extension"
        assert extension.confidence == 0.7

        virtual = by_callee["App.Extensions.Base.Greet"]
        assert virtual.kind == "virtual"
        assert virtual.confidence == 0.7

        assert direct.caller == "App.Controllers.UserController.CreateUser"
        assert direct.file_path == "UserController.cs"
        assert direct.line == 11

    def test_nonzero_exit_code_returns_empty_list(self, fake_tool_present, monkeypatch):
        def _run(cmd, timeout_seconds, cwd=None):
            return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="build failed")
        monkeypatch.setattr("security_review.tools.runner.run_tool_sync", _run)

        edges = build_csharp_call_edges(fake_tool_present, fake_tool_present / "App.csproj")
        assert edges == []

    def test_missing_output_file_returns_empty_list(self, fake_tool_present, monkeypatch):
        def _run(cmd, timeout_seconds, cwd=None):
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        monkeypatch.setattr("security_review.tools.runner.run_tool_sync", _run)

        edges = build_csharp_call_edges(fake_tool_present, fake_tool_present / "App.csproj")
        assert edges == []

    def test_invalid_json_returns_empty_list(self, fake_tool_present, monkeypatch):
        output_path = fake_tool_present / ".scar" / "roslyn-callgraph.json"

        def _run(cmd, timeout_seconds, cwd=None):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("not json{{{", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")
        monkeypatch.setattr("security_review.tools.runner.run_tool_sync", _run)

        edges = build_csharp_call_edges(fake_tool_present, fake_tool_present / "App.csproj")
        assert edges == []
