"""Integration test: betterleaks scan for hardcoded secrets."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from security_review.tools.registry import load_tool_specs
from security_review.tools.runner import run_tool


@pytest.fixture
def betterleaks_spec():
    specs = load_tool_specs()
    for s in specs:
        if s.name == "betterleaks":
            return s
    return None


@pytest.mark.skipif(
    not shutil.which("betterleaks"),
    reason="betterleaks not installed",
)
@pytest.mark.asyncio
async def test_betterleaks_detects_hardcoded_secret(betterleaks_spec, tmp_path):
    """Run betterleaks against a file with a hardcoded secret."""
    target_dir = tmp_path / "app"
    target_dir.mkdir()
    secret_file = target_dir / "config.py"
    secret_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    )

    output_path = str(tmp_path / "betterleaks.sarif")
    result = await run_tool(betterleaks_spec, str(target_dir), output_path)

    assert result.exit_code in betterleaks_spec.success_exit_codes
    assert result.success
    assert betterleaks_spec.redact_output is True


@pytest.mark.skipif(
    not shutil.which("betterleaks"),
    reason="betterleaks not installed",
)
@pytest.mark.asyncio
async def test_betterleaks_clean_app_no_secrets(betterleaks_spec, tmp_path, clean_python_app):
    """Run betterleaks against a clean file — expect exit code 0."""
    output_path = str(tmp_path / "betterleaks-clean.sarif")
    result = await run_tool(betterleaks_spec, str(clean_python_app), output_path)

    assert result.exit_code == 0
    assert result.success
