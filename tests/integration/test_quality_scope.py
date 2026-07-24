"""Integration test: quality scorer excludes the same files bandit scans (Plan 021 WP-E).

Real bandit run — verifies the fix end-to-end, not just the args it is
invoked with (see tests/unit/test_code_quality/test_scope_alignment.py for
the argument-level unit tests).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from code_quality.score import score_project

pytestmark = pytest.mark.skipif(not shutil.which("bandit"), reason="bandit not installed")


def test_bandit_excludes_venv_dir_from_security_score(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "clean.py").write_text("x = 1\n", encoding="utf-8")

    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "evil.py").write_text(
        "import subprocess\nsubprocess.run('ls', shell=True)\n", encoding="utf-8",
    )

    result = score_project(tmp_path, tools=["bandit"], include_graph=False)

    security = result.dimensions["security"]
    # bandit_high_severity is exp_decay(high_severity_count, ...) — exactly
    # 100.0 at count=0. If .venv/evil.py leaked into the scan, this would be
    # a fraction (exp_decay(1, rate=1.5) ~= 22.3), and a recommendation about
    # the HIGH finding would be present.
    assert security.sub_scores["bandit_high_severity"] == 100.0
    assert not any("HIGH severity" in r for r in security.recommendations)
