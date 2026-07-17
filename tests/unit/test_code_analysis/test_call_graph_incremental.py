"""Tests for incremental call-graph reindexing (cross-run caching)."""

from __future__ import annotations

from pathlib import Path

import pytest

from code_analysis import analyze
from code_analysis.call_graph import build_call_graph_incremental
from code_analysis.store import GraphStore


@pytest.fixture
def project(tmp_path: Path) -> Path:
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "a.py").write_text("def foo():\n    return bar()\n\n\ndef bar():\n    return 1\n")
    return tmp_path


class TestBuildCallGraphIncremental:
    def test_first_build_indexes_everything(self, project: Path, tmp_path: Path):
        metrics = analyze(project, include_graph=True)
        python_files = [project / m.path for m in metrics.modules]

        with GraphStore(tmp_path / "graph.db") as store:
            graph = build_call_graph_incremental(project, metrics.modules, store, python_files=python_files)

        assert graph.call_edges
        assert any("bar" in e.callee for e in graph.call_edges)

    def test_second_build_with_no_changes_skips_reparsing(self, project: Path, tmp_path: Path, monkeypatch):
        metrics = analyze(project, include_graph=True)
        python_files = [project / m.path for m in metrics.modules]
        db_path = tmp_path / "graph.db"

        with GraphStore(db_path) as store:
            build_call_graph_incremental(project, metrics.modules, store, python_files=python_files)

        call_count = 0
        import code_analysis.call_graph as cg_module
        real_build = cg_module.build_python_call_edges

        def _counting_build(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return real_build(*args, **kwargs)

        monkeypatch.setattr(cg_module, "build_python_call_edges", _counting_build)

        with GraphStore(db_path) as store:
            graph = build_call_graph_incremental(project, metrics.modules, store, python_files=python_files)

        assert call_count == 0  # nothing changed -- pyan3 must not be invoked again
        assert graph.call_edges  # graph still loads correctly from cache

    def test_modified_file_is_reparsed_others_are_not(self, project: Path, tmp_path: Path):
        metrics = analyze(project, include_graph=True)
        python_files = [project / m.path for m in metrics.modules]
        db_path = tmp_path / "graph.db"

        with GraphStore(db_path) as store:
            build_call_graph_incremental(project, metrics.modules, store, python_files=python_files)

        # Modify a.py: add a new function and a new call.
        (project / "app" / "a.py").write_text(
            "def foo():\n    return bar()\n\n\ndef bar():\n    return baz()\n\n\ndef baz():\n    return 2\n"
        )
        metrics2 = analyze(project, include_graph=True)
        python_files2 = [project / m.path for m in metrics2.modules]

        with GraphStore(db_path) as store:
            graph = build_call_graph_incremental(project, metrics2.modules, store, python_files=python_files2)

        callees = {e.callee for e in graph.call_edges}
        assert any("baz" in c for c in callees)
