"""Tests for one file-set resolution shared by AST + tool scoring (Plan 021 WP-E).

score_project must resolve `exclude` ONCE and pass the same effective list to
both analyze() (AST dimensions) and run_tools() (bandit/radon) -- otherwise
bandit scores files the AST dimensions never measured (e.g. .venv/, eval/).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from code_quality.score import score_project


@pytest.fixture
def captured_bandit_args(monkeypatch) -> list[list[str]]:
    """Stub code_quality.tools._run_command and capture every invocation's
    argv, standing in for a real bandit binary."""
    captured: list[list[str]] = []

    def _fake_run_command(args, cwd, timeout=120):
        captured.append(args)
        return '{"results": [], "metrics": {}}', "", 0

    monkeypatch.setattr("code_quality.tools._run_command", _fake_run_command)
    return captured


def test_bandit_receives_exclude_defaults_when_none_given(tmp_path: Path, captured_bandit_args):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "clean.py").write_text("x = 1\n", encoding="utf-8")
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "evil.py").write_text("x = 1\n", encoding="utf-8")

    score_project(tmp_path, tools=["bandit"], exclude=None)

    assert len(captured_bandit_args) == 1
    bandit_args = captured_bandit_args[0]
    assert "--exclude" in bandit_args
    exclude_value = bandit_args[bandit_args.index("--exclude") + 1]
    assert str(venv_dir) in exclude_value.split(",")


def test_bandit_receives_no_exclude_when_default_dirs_absent(tmp_path: Path, captured_bandit_args):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "clean.py").write_text("x = 1\n", encoding="utf-8")

    score_project(tmp_path, tools=["bandit"], exclude=None)

    assert len(captured_bandit_args) == 1
    assert "--exclude" not in captured_bandit_args[0]


def test_explicit_exclude_is_still_honoured_verbatim(tmp_path: Path, captured_bandit_args):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "clean.py").write_text("x = 1\n", encoding="utf-8")
    custom_dir = tmp_path / "vendor"
    custom_dir.mkdir()
    (custom_dir / "thirdparty.py").write_text("x = 1\n", encoding="utf-8")

    score_project(tmp_path, tools=["bandit"], exclude=["vendor/"])

    exclude_value = captured_bandit_args[0][captured_bandit_args[0].index("--exclude") + 1]
    assert exclude_value.split(",") == [str(custom_dir)]
