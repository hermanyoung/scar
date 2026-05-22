"""Integration test: Bandit scan against Python eval corpus."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from security_review.tools.registry import load_tool_specs
from security_review.tools.runner import run_tool

EVAL_ROOT = Path(__file__).resolve().parent.parent.parent / "eval"


@pytest.fixture
def bandit_spec():
    specs = load_tool_specs()
    for s in specs:
        if s.name == "bandit":
            return s
    return None


@pytest.mark.skipif(
    not shutil.which("bandit"),
    reason="bandit not installed",
)
@pytest.mark.asyncio
async def test_bandit_scans_command_injection(bandit_spec, tmp_path):
    """Run Bandit against corpus/python/cwe-078 and verify exit code 1 = success."""
    corpus_dir = EVAL_ROOT / "python" / "cwe-078-os-command-injection" / "source"
    if not corpus_dir.exists():
        pytest.skip("Corpus directory not found")

    output_path = str(tmp_path / "bandit.sarif")
    result = await run_tool(bandit_spec, str(corpus_dir), output_path)

    # Bandit returns exit code 1 when findings are present — this is success
    assert result.exit_code in bandit_spec.success_exit_codes, (
        f"Bandit exited with {result.exit_code}, stderr: {result.stderr[:300]}"
    )
    assert result.success

    # Verify SARIF output was created
    assert Path(output_path).exists()


@pytest.mark.skipif(
    not shutil.which("bandit"),
    reason="bandit not installed",
)
@pytest.mark.asyncio
async def test_bandit_clean_app_no_findings(bandit_spec, tmp_path, clean_python_app):
    """Run Bandit against a secure Python file — expect exit code 0, no findings."""
    output_path = str(tmp_path / "bandit-clean.sarif")
    result = await run_tool(bandit_spec, str(clean_python_app), output_path)

    # Exit code 0 = no findings
    assert result.exit_code == 0
    assert result.success
