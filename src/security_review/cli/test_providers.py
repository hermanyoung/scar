"""CLI command: test-providers — test LLM provider compatibility."""
from __future__ import annotations

import subprocess
import sys

import click

from security_review.cli.app import PROJECT_ROOT, cli


@cli.command("test-providers")
@click.option("--models", default=None, help="Comma-separated model strings (e.g. copilot:claude-opus-4.6).")
@click.option("--copilot", "group_copilot", is_flag=True, help="Test all Copilot models.")
@click.option("--api", "group_api", is_flag=True, help="Test OpenAI + Anthropic API models.")
@click.option("--all", "group_all", is_flag=True, help="Test everything.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="DEBUG-level logging.")
def test_providers(models, group_copilot, group_api, group_all, verbose, debug):
    """Test LLM provider compatibility."""
    # NOTE: subprocess.call is acceptable here — this file is the CLI entry point
    # outside src/security_review/. P2 subprocess isolation applies to the module only.
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "test_providers.py")]

    if group_all:
        cmd.append("--all")
    elif group_copilot:
        cmd.append("--copilot")
    elif group_api:
        cmd.append("--api")
    elif models:
        cmd.extend(models.split(","))
    else:
        cmd.append("--copilot")

    raise SystemExit(subprocess.call(cmd))
