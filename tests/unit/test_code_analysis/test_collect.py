"""Tests for file collection."""

from pathlib import Path

import pytest

from code_analysis.collect import collect_files, _matches_exclude


FIXTURES = Path(__file__).parent / "fixtures"


class TestCollectFiles:
    def test_finds_python_files(self):
        files = collect_files(FIXTURES, extensions={".py"})
        assert len(files) >= 3  # clean.py, complex.py, unsafe.py
        assert all(f.suffix == ".py" for f in files)

    def test_scope_limits_to_directory(self):
        files = collect_files(FIXTURES, scope=["python/"], extensions={".py"})
        assert len(files) >= 3
        assert all("python" in str(f) for f in files)

    def test_exclude_filters_out_patterns(self):
        files = collect_files(FIXTURES, extensions={".py"}, exclude=["*unsafe*"])
        names = [f.name for f in files]
        assert "unsafe.py" not in names
        assert "clean.py" in names

    def test_empty_directory(self, tmp_path):
        files = collect_files(tmp_path, extensions={".py"})
        assert files == []

    def test_extensions_filter(self):
        # Only look for .cs files in python fixture dir
        files = collect_files(FIXTURES / "python", extensions={".cs"})
        assert files == []


class TestMatchesExclude:
    def test_directory_pattern(self):
        assert _matches_exclude("__pycache__/foo.pyc", "__pycache__/")
        assert not _matches_exclude("src/main.py", "__pycache__/")

    def test_glob_pattern(self):
        assert _matches_exclude("foo.designer.cs", "*.designer.cs")
        assert not _matches_exclude("foo.cs", "*.designer.cs")

    def test_prefix_pattern(self):
        assert _matches_exclude("obj/Debug/foo.dll", "obj/")
        assert not _matches_exclude("src/obj_helper.py", "obj/")
