"""Tests for the analyze() orchestrator."""

from pathlib import Path

import pytest

from code_analysis import analyze, list_languages


FIXTURES = Path(__file__).parent / "fixtures"


class TestAnalyze:
    def test_analyzes_python_fixtures(self):
        result = analyze(FIXTURES, languages=["python"])
        assert result.source_files >= 3
        assert result.source_lines > 0
        assert all(f.language == "python" for f in result.files)

    def test_no_graph_by_default(self):
        result = analyze(FIXTURES, languages=["python"])
        assert result.graph is None
        assert result.ranks == {}
        assert result.modules == []

    def test_graph_when_requested(self):
        result = analyze(FIXTURES, languages=["python"], include_graph=True)
        assert result.graph is not None
        assert len(result.graph.nodes) > 0
        assert len(result.modules) >= 3

    def test_pre_discovered_files(self):
        files = [FIXTURES / "python" / "clean.py"]
        result = analyze(FIXTURES, files=files)
        assert result.source_files == 1
        assert result.files[0].path == "python/clean.py"

    def test_empty_directory(self, tmp_path):
        result = analyze(tmp_path)
        assert result.source_files == 0
        assert result.files == []
        assert result.graph is None

    def test_language_filter(self):
        result = analyze(FIXTURES, languages=["csharp"])
        # No .cs files in fixtures/python/
        # May find .cs fixtures if they exist, otherwise 0
        assert all(f.language == "csharp" for f in result.files)


class TestListLanguages:
    def test_includes_python(self):
        assert "python" in list_languages()

    def test_includes_csharp(self):
        assert "csharp" in list_languages()
