"""Tests for the CWE check registry (Plan 019 WP-G / plan 002 §2.1 remainder)."""
from __future__ import annotations

from security_review.checks import CWECheck, load_cwe_checks, select_files_for_check
from security_review.models.inventory import FileEntry


def _entry(path: str, language: str = "csharp") -> FileEntry:
    return FileEntry(path=path, language=language, size_bytes=100,
                     security_weight=1, estimated_tokens=25)


def test_load_cwe_checks_returns_checks():
    checks = load_cwe_checks()
    assert len(checks) > 0


def test_every_check_has_prompt_and_file_types():
    for check in load_cwe_checks():
        assert check.check_prompt, f"CWE-{check.cwe_id} has an empty check prompt"
        assert check.file_types, f"CWE-{check.cwe_id} has no file_types"


def test_863_check_contains_severity_rubric():
    checks = {c.cwe_id: c for c in load_cwe_checks()}
    assert "863" in checks
    assert "Severity rubric" in checks["863"].check_prompt


def test_select_files_for_check_matches_controller_and_excludes_readme():
    check = CWECheck(
        cwe_id="862", name="Missing Authorization", detection="llm",
        file_types=["controller"], check_prompt="Check authorization.",
    )
    files = [
        _entry("Controllers/UserController.cs"),
        _entry("README.md", language="markdown"),
    ]

    selected = select_files_for_check(check, files)

    paths = [f.path for f in selected]
    assert "Controllers/UserController.cs" in paths
    assert "README.md" not in paths
