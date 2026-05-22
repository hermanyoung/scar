"""Integration test: OpenGrep scan against Python eval corpus."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from security_review.tools.registry import SecurityToolSpec, load_tool_specs
from security_review.tools.runner import run_tool

EVAL_ROOT = Path(__file__).resolve().parent.parent.parent / "eval"


@pytest.fixture
def opengrep_spec() -> SecurityToolSpec | None:
    specs = load_tool_specs()
    for s in specs:
        if s.name == "opengrep":
            return s
    return None


@pytest.mark.skipif(
    not shutil.which("opengrep"),
    reason="opengrep not installed",
)
@pytest.mark.asyncio
async def test_opengrep_scans_python_code_injection(opengrep_spec, tmp_path):
    """Run OpenGrep against corpus/python/cwe-094-code-injection and verify findings."""
    corpus_dir = EVAL_ROOT / "python" / "cwe-094-code-injection" / "source"
    if not corpus_dir.exists():
        pytest.skip("Corpus directory not found")

    output_path = str(tmp_path / "opengrep.sarif")
    result = await run_tool(opengrep_spec, str(corpus_dir), output_path)

    # opengrep returns exit code 1 when findings exist
    assert result.exit_code in opengrep_spec.success_exit_codes
    assert result.success

    # Verify SARIF output was created
    assert Path(output_path).exists()
