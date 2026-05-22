"""Integration test: automated eval scorer.

Discovers all eval entries with expected.sarif, runs applicable SAST tools,
and compares actual findings against expected ground truth.

Requires SAST tools on PATH (opengrep, bandit, etc). Skipped if none available.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.eval.runner import (
    compare_results,
    discover_eval_entries,
    get_source_files,
    load_expected,
    run_sast_for_entry,
)


def _has_any_sast_tool() -> bool:
    """Check if at least one SAST tool is available."""
    return any(shutil.which(t) for t in ("opengrep", "bandit"))


def _entry_id(entry: Path) -> str:
    """Generate a readable test ID from an eval entry path."""
    parts = entry.parts
    # Find 'eval' in path and take everything after
    try:
        idx = parts.index("eval")
        return "/".join(parts[idx + 1:])
    except ValueError:
        return str(entry.name)


# Discover all eval entries at module load time for parametrize
_entries = discover_eval_entries()


@pytest.mark.skipif(
    not _has_any_sast_tool(),
    reason="No SAST tools installed (need opengrep or bandit)",
)
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "eval_entry",
    _entries,
    ids=[_entry_id(e) for e in _entries],
)
async def test_eval_entry(eval_entry: Path, tmp_path: Path):
    """Run SAST tools against an eval entry and compare to expected.sarif."""
    expected = load_expected(eval_entry)
    source_files = get_source_files(eval_entry)

    if not source_files:
        pytest.skip(f"No source files in {eval_entry}")

    actual = await run_sast_for_entry(eval_entry, tmp_path)

    # compare_results matches on (file, line) location pairs — rule IDs
    # differ between tools (OpenGrep vs Bandit) so they're not used for matching.
    result = compare_results(actual, expected)

    if not result["pass"]:
        missing = result["missing"]
        unexpected = result["unexpected"]
        lines = [f"Eval entry: {_entry_id(eval_entry)}"]
        if missing:
            lines.append(f"  MISSING ({len(missing)} expected findings not detected):")
            for rule_id, uri, line in missing:
                lines.append(f"    {rule_id}  {uri}:{line}")
        if unexpected:
            lines.append(f"  UNEXPECTED ({len(unexpected)} findings not in expected.sarif):")
            for rule_id, uri, line in unexpected:
                lines.append(f"    {rule_id}  {uri}:{line}")
        pytest.fail("\n".join(lines))
