"""Integration test: every OpenGrep rule satisfies its own ruleid:/ok: annotations.

AGENTS.md requires each rule to ship a matching test file annotated with
`ruleid:` (must match) and `ok:` (must not match). Nothing ever ran those
annotations, so rules shipped whose own tests failed: the CWE-918 SSRF rule
matched every dict `.get()` call in Python and produced 477 of 538 findings in
a self-scan before anyone noticed.

Each rule is checked in its own opengrep invocation rather than one pass over
the tree, because a single malformed rule aborts a whole-tree run and would
mask every other result.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from security_review.tools.registry import load_tool_specs
from security_review.tools.runner import run_tool_sync

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_ROOT = REPO_ROOT / "config" / "rules" / "opengrep"

# A rule's test file shares its stem and sits beside it; opengrep picks the
# language from the extension.
TEST_FILE_SUFFIXES = (".py", ".cs", ".dockerfile", ".tf", ".json", ".yml")

requires_opengrep = pytest.mark.skipif(
    not shutil.which("opengrep"), reason="opengrep not installed"
)


def _rule_files() -> list[Path]:
    return sorted(RULES_ROOT.rglob("*.yaml"))


def _rule_id(path: Path) -> str:
    return str(path.relative_to(RULES_ROOT))


def _test_file_for(rule_path: Path) -> Path | None:
    for suffix in TEST_FILE_SUFFIXES:
        candidate = rule_path.with_suffix(suffix)
        if candidate.exists():
            return candidate
    return None


def _opengrep_timeout() -> int:
    """Reuse the scanner's own timeout rather than inventing one here."""
    for spec in load_tool_specs():
        if spec.name == "opengrep":
            return spec.timeout_seconds
    raise AssertionError("opengrep spec missing from tools/specs")


@requires_opengrep
@pytest.mark.parametrize("rule_path", _rule_files(), ids=_rule_id)
def test_rule_satisfies_its_own_annotations(rule_path: Path) -> None:
    """Every ruleid: line must match and every ok: line must not."""
    test_file = _test_file_for(rule_path)
    assert test_file is not None, (
        f"{_rule_id(rule_path)} has no sibling test file. AGENTS.md requires "
        f"one with ruleid:/ok: annotations."
    )

    completed = run_tool_sync(
        [
            "opengrep",
            "--test",
            "--json",
            "--config",
            str(rule_path),
            str(test_file),
        ],
        timeout_seconds=_opengrep_timeout(),
        cwd=str(REPO_ROOT),
    )

    # A rule that fails to load emits no JSON at all -- the reason is on stderr,
    # and it is a real defect (e.g. an annotation naming a rule that never
    # matches), so surface it rather than skipping.
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        pytest.fail(
            f"{_rule_id(rule_path)}: opengrep produced no test report.\n"
            f"stderr: {completed.stderr.strip()}"
        )

    failures = []
    for config_path, body in report.get("results", {}).items():
        for check_id, check in body.get("checks", {}).items():
            if check.get("passed"):
                continue
            for matched_file, lines in (check.get("matches") or {}).items():
                expected = set(lines.get("expected_lines") or [])
                reported = set(lines.get("reported_lines") or [])
                failures.append(
                    f"{check_id}\n"
                    f"    missed (expected a finding): {sorted(expected - reported)}\n"
                    f"    over-matched (annotated ok): {sorted(reported - expected)}"
                )

    assert not failures, (
        f"{_rule_id(rule_path)} does not satisfy its own annotations:\n"
        + "\n".join(failures)
    )


@requires_opengrep
def test_every_rule_ships_a_test_file() -> None:
    """AGENTS.md makes the test file mandatory; this is what enforces it."""
    missing = [_rule_id(p) for p in _rule_files() if _test_file_for(p) is None]
    assert not missing, (
        "Rules without a sibling test file: " + ", ".join(missing)
    )
