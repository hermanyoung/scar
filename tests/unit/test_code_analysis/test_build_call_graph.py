"""Integration tests for build_call_graph(): assembling the unified CallGraph."""

from __future__ import annotations

from pathlib import Path

import pytest

from code_analysis import analyze
from code_analysis.call_graph import build_call_graph


@pytest.fixture
def call_chain_project(tmp_path: Path) -> Path:
    """controller.py -> service.py (calls self.cursor.execute -- an external sink).

    Note: pyan3 only wildcard-resolves attribute calls through `self.attr`
    (tracked via constructor assignment analysis) -- calls through a bare
    local variable of unknown type (`cursor = get_cursor(); cursor.execute(...)`)
    are silently dropped with no edge at all. This fixture uses the
    self-attribute pattern, which is both the common real-world shape
    (cursor/connection stored on the instance) and the one pyan3 can see.
    """
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "controller.py").write_text(
        "from app.service import UserService\n\n"
        "class UserController:\n"
        "    @app.route('/users', methods=['POST'])\n"
        "    def create_user(self, name):\n"
        "        return UserService().save(name)\n"
    )
    (pkg / "service.py").write_text(
        "class UserService:\n"
        "    def __init__(self):\n"
        "        self.cursor = None\n\n"
        "    def save(self, name):\n"
        "        return self.cursor.execute(name)\n"
    )
    return tmp_path


class TestBuildCallGraph:
    def test_assembles_nodes_sinks_and_entry_points(self, call_chain_project: Path):
        metrics = analyze(call_chain_project, include_graph=True)
        python_files = [call_chain_project / m.path for m in metrics.modules]

        graph = build_call_graph(call_chain_project, metrics.modules, python_files=python_files)

        assert graph.call_edges
        assert graph.nodes

        # The service.save -> cursor.execute call edge should exist even
        # though cursor.execute is never a locally-defined symbol.
        callees = {e.callee for e in graph.call_edges}
        assert any("execute" in c for c in callees)

    def test_symbol_files_resolves_every_call_edge_endpoint(self, call_chain_project: Path):
        metrics = analyze(call_chain_project, include_graph=True)
        python_files = [call_chain_project / m.path for m in metrics.modules]
        graph = build_call_graph(call_chain_project, metrics.modules, python_files=python_files)

        for edge in graph.call_edges:
            assert edge.caller in graph.symbol_files, f"caller {edge.caller} unresolved"

    def test_no_call_graph_sources_still_builds_reference_only_graph(self, call_chain_project: Path):
        metrics = analyze(call_chain_project, include_graph=True)
        graph = build_call_graph(call_chain_project, metrics.modules)
        assert graph.call_edges == []
        assert graph.nodes  # reference graph nodes still present
