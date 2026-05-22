"""Tests for tool registry: spec loading, command building, file matching."""
from __future__ import annotations

from security_review.tools.registry import SecurityToolSpec, load_tool_specs


def test_load_tool_specs():
    specs = load_tool_specs()
    assert len(specs) >= 7
    names = {s.name for s in specs}
    assert "bandit" in names
    assert "opengrep" in names
    assert "betterleaks" in names


def test_build_command():
    spec = SecurityToolSpec(
        name="test-tool",
        binary="test-bin",
        version_cmd=["test-bin", "--version"],
        output_format="sarif",
        sarif_native=True,
        arg_template=["{binary}", "--input", "{target_path}", "--output", "{output_path}"],
    )
    cmd = spec.build_command("/src/app", "/tmp/out.sarif")
    assert cmd == ["test-bin", "--input", "/src/app", "--output", "/tmp/out.sarif"]


def test_matches_files_python():
    spec = SecurityToolSpec(
        name="bandit",
        binary="bandit",
        version_cmd=["bandit", "--version"],
        output_format="sarif",
        sarif_native=True,
        arg_template=["{binary}", "{target_path}"],
        applies_to=["*.py"],
    )
    assert spec.matches_files(["app.py", "models.py"]) is True
    assert spec.matches_files(["app.cs"]) is False


def test_matches_files_empty_applies_to():
    spec = SecurityToolSpec(
        name="gitleaks",
        binary="gitleaks",
        version_cmd=["gitleaks", "version"],
        output_format="sarif",
        sarif_native=True,
        arg_template=["{binary}"],
        applies_to=[],
    )
    assert spec.matches_files(["anything.txt"]) is True


def test_build_command_with_default_args():
    spec = SecurityToolSpec(
        name="opengrep",
        binary="opengrep",
        version_cmd=["opengrep", "--version"],
        output_format="sarif",
        sarif_native=True,
        arg_template=["{binary}", "scan", "--config", "{rules_path}", "{target_path}"],
        default_args={"rules_path": "config/rules/opengrep"},
    )
    cmd = spec.build_command("/src", "/tmp/out.sarif")
    assert cmd[3] == "config/rules/opengrep"
