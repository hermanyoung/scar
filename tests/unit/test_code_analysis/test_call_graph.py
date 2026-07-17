"""Tests for Python call graph extraction (pyan3-backed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from code_analysis.call_graph import build_python_call_edges


@pytest.fixture
def call_chain_project(tmp_path: Path) -> Path:
    """controller.py -> service.py -> store.py, mirroring a real request path."""
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "controller.py").write_text(
        "from app.service import UserService\n\n"
        "class UserController:\n"
        "    def create_user(self, name):\n"
        "        return UserService().save(name)\n"
    )
    (pkg / "service.py").write_text(
        "from app.store import UserStore\n\n"
        "class UserService:\n"
        "    def save(self, name):\n"
        "        return UserStore().insert(name)\n"
    )
    (pkg / "store.py").write_text(
        "class UserStore:\n"
        "    def insert(self, name):\n"
        "        return name\n"
    )
    return tmp_path


class TestBuildPythonCallEdges:
    def test_empty_input_returns_empty_list(self, tmp_path: Path):
        assert build_python_call_edges(tmp_path, []) == []

    def test_extracts_call_chain_with_correct_qualified_names(self, call_chain_project: Path):
        files = sorted(call_chain_project.glob("app/*.py"))
        edges = build_python_call_edges(call_chain_project, files)

        callers = {e.caller for e in edges}
        assert "app.controller.UserController.create_user" in callers
        assert "app.service.UserService.save" in callers

        # controller.create_user calls UserService.save (directly or via UserService())
        controller_edges = [e for e in edges if e.caller == "app.controller.UserController.create_user"]
        callees = {e.callee for e in controller_edges}
        assert any("UserService" in c for c in callees)

        service_edges = [e for e in edges if e.caller == "app.service.UserService.save"]
        callees = {e.callee for e in service_edges}
        assert any("UserStore" in c for c in callees)

    def test_edge_file_path_is_relative_to_root(self, call_chain_project: Path):
        files = sorted(call_chain_project.glob("app/*.py"))
        edges = build_python_call_edges(call_chain_project, files)
        controller_edges = [e for e in edges if "controller" in e.caller]
        assert controller_edges
        assert controller_edges[0].file_path == "app/controller.py"

    def test_pyan3_not_installed_returns_empty_list(self, call_chain_project: Path, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "pyan.analyzer":
                raise ImportError("simulated: pyan3 not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        files = sorted(call_chain_project.glob("app/*.py"))
        edges = build_python_call_edges(call_chain_project, files)
        assert edges == []
