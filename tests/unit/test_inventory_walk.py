"""Tests for pruned directory walk + exclude/include filters (Plan 018 WP9)."""
from __future__ import annotations

from pathlib import Path

from security_review.passes.inventory import _walk_files


def _make_tree(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')")
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "index.js").write_text("module.exports = {}")
    (tmp_path / "pkg.egg-info").mkdir()
    (tmp_path / "pkg.egg-info" / "x.py").write_text("# generated")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("# vendored")


def test_default_walk_excludes_node_modules_and_egg_info(tmp_path: Path):
    _make_tree(tmp_path)
    files = _walk_files(tmp_path, max_size=1_048_576)
    names = {str(f.relative_to(tmp_path)).replace("\\", "/") for f in files}
    assert names == {"src/app.py", "vendor/lib.py"}


def test_exclude_glob_drops_matching_path(tmp_path: Path):
    _make_tree(tmp_path)
    files = _walk_files(tmp_path, max_size=1_048_576, exclude=("vendor/*",))
    names = {str(f.relative_to(tmp_path)).replace("\\", "/") for f in files}
    assert names == {"src/app.py"}


def test_include_glob_restricts_to_matching_path(tmp_path: Path):
    _make_tree(tmp_path)
    files = _walk_files(tmp_path, max_size=1_048_576, include=("src/*",))
    names = {str(f.relative_to(tmp_path)).replace("\\", "/") for f in files}
    assert names == {"src/app.py"}


def test_file_over_max_size_skipped(tmp_path: Path):
    _make_tree(tmp_path)
    (tmp_path / "big.py").write_text("x" * 2000)
    files = _walk_files(tmp_path, max_size=100)
    names = {str(f.relative_to(tmp_path)).replace("\\", "/") for f in files}
    assert "big.py" not in names
