"""Tests for Pass 1 inventory: file discovery, exclusions, security weighting."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from security_review.config_schema import SecurityReviewConfig
from security_review.passes.inventory import _compute_security_weight, _walk_files


def test_walk_files_excludes_pycache(tmp_path: Path):
    """I-01: excludes __pycache__/"""
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "module.pyc").write_text("bytecode")
    (tmp_path / "app.py").write_text("print('hello')")

    files = _walk_files(tmp_path, max_size=1_048_576)
    names = [f.name for f in files]
    assert "app.py" in names
    assert "module.pyc" not in names


def test_walk_files_excludes_node_modules(tmp_path: Path):
    """I-01: excludes node_modules/"""
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("module.exports = {}")
    (tmp_path / "app.py").write_text("print('hello')")

    files = _walk_files(tmp_path, max_size=1_048_576)
    names = [f.name for f in files]
    assert "index.js" not in names


def test_walk_files_excludes_bin_obj(tmp_path: Path):
    """I-01: excludes obj/ and bin/"""
    (tmp_path / "obj" / "Debug").mkdir(parents=True)
    (tmp_path / "obj" / "Debug" / "output.dll").write_text("binary")
    (tmp_path / "bin" / "Release").mkdir(parents=True)
    (tmp_path / "bin" / "Release" / "app.exe").write_text("binary")
    (tmp_path / "Program.cs").write_text("class Program {}")

    files = _walk_files(tmp_path, max_size=1_048_576)
    names = [f.name for f in files]
    assert "output.dll" not in names
    assert "app.exe" not in names
    assert "Program.cs" in names


def test_walk_files_excludes_designer_cs(tmp_path: Path):
    """I-01: excludes *.designer.cs"""
    (tmp_path / "Form1.designer.cs").write_text("generated")
    (tmp_path / "Form1.cs").write_text("user code")

    files = _walk_files(tmp_path, max_size=1_048_576)
    names = [f.name for f in files]
    assert "Form1.designer.cs" not in names
    assert "Form1.cs" in names


def test_walk_files_respects_max_size(tmp_path: Path):
    small = tmp_path / "small.py"
    small.write_text("x = 1")
    large = tmp_path / "large.py"
    large.write_text("x" * 2000)

    files = _walk_files(tmp_path, max_size=100)
    names = [f.name for f in files]
    assert "small.py" in names
    assert "large.py" not in names


def test_security_weight_controller(tmp_path: Path):
    """I-02: Controller files get security weight >= 2."""
    ctrl = tmp_path / "UserController.cs"
    ctrl.write_text("[ApiController] public class UserController {}")
    weight = _compute_security_weight(ctrl, "csharp")
    assert weight >= 2


def test_security_weight_eval(tmp_path: Path):
    """I-02: Files with eval() get security weight >= 2."""
    app = tmp_path / "processor.py"
    app.write_text("result = eval(user_input)")
    weight = _compute_security_weight(app, "python")
    assert weight >= 2


def test_security_weight_other_language(tmp_path: Path):
    """Other language files get weight 0."""
    txt = tmp_path / "readme.txt"
    txt.write_text("Just a readme")
    weight = _compute_security_weight(txt, "other")
    assert weight == 0
