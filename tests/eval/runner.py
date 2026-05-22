"""Eval harness — runs SAST tools against eval entries, compares to expected.sarif.

Functions:
    load_expected()       — load (ruleId, file, line) tuples from expected.sarif
    compare_results()     — diff actual vs expected finding tuples
    discover_eval_entries() — find all eval entries with expected.sarif
    run_sast_for_entry()  — run applicable SAST tools, return actual finding tuples
"""
from __future__ import annotations

import json
from pathlib import Path

from security_review import MODULE_ROOT

EVAL_ROOT = MODULE_ROOT / "eval"


def discover_eval_entries() -> list[Path]:
    """Find all eval entries that have an expected.sarif file."""
    return sorted(p.parent for p in EVAL_ROOT.rglob("expected.sarif"))


def load_expected(eval_entry: Path) -> list[tuple[str, str, int]]:
    """Load expected findings from an eval entry's expected.sarif."""
    expected_path = eval_entry / "expected.sarif"
    if not expected_path.exists():
        return []

    with open(expected_path, encoding="utf-8") as f:
        sarif = json.load(f)

    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                findings.append((rule_id, uri, line))

    return findings


def compare_results(
    actual: list[tuple[str, str, int]],
    expected: list[tuple[str, str, int]],
) -> dict:
    """Compare actual vs expected findings by location (file, line).

    Matching is location-based: an expected finding at (file, line) is
    satisfied if ANY tool produced a finding at that same (file, line).
    Rule IDs differ between tools (OpenGrep vs Bandit) so they're not
    used for matching — only for reporting.
    """
    actual_locations = {(f, l) for _, f, l in actual}
    expected_locations = {(f, l) for _, f, l in expected}

    matched_locs = actual_locations & expected_locations
    missing_locs = expected_locations - actual_locations
    unexpected_locs = actual_locations - expected_locations

    # Map locations back to full tuples for reporting
    matched = sorted(t for t in expected if (t[1], t[2]) in matched_locs)
    missing = sorted(t for t in expected if (t[1], t[2]) in missing_locs)
    unexpected = sorted(t for t in actual if (t[1], t[2]) in unexpected_locs)

    return {
        "matched": matched,
        "missing": missing,
        "unexpected": unexpected,
        "pass": len(missing_locs) == 0,
    }


def get_source_dir(eval_entry: Path) -> Path:
    """Get the directory containing source files for an eval entry.

    Returns source/ subdirectory if it exists, otherwise the entry root
    (for entries like false-positives where files sit at top level).
    """
    source_dir = eval_entry / "source"
    if source_dir.is_dir():
        return source_dir
    return eval_entry


def get_source_files(eval_entry: Path) -> list[str]:
    """List source file names in an eval entry (for tool matching)."""
    source_dir = get_source_dir(eval_entry)
    extensions = {".py", ".cs", ".razor", ".csproj"}
    files = []
    for f in source_dir.iterdir():
        if f.is_file() and f.suffix in extensions:
            files.append(f.name)
    # Also check for Dockerfiles
    for f in source_dir.iterdir():
        if f.is_file() and f.name.startswith("Dockerfile"):
            files.append(f.name)
    return files


async def run_sast_for_entry(eval_entry: Path, tmp_dir: Path) -> list[tuple[str, str, int]]:
    """Run applicable SAST tools against an eval entry, return actual finding tuples.

    Returns list of (ruleId, filename, startLine) tuples extracted from SARIF output.
    Only runs tools that are available on PATH and match the entry's file types.
    """
    from security_review.sarif.loader import load_sarif
    from security_review.tools.registry import load_tool_specs
    from security_review.tools.runner import run_tool

    source_dir = get_source_dir(eval_entry)
    source_files = get_source_files(eval_entry)
    if not source_files:
        return []

    specs = load_tool_specs()
    findings: list[tuple[str, str, int]] = []

    for spec in specs:
        if not spec.is_available():
            continue
        if not spec.matches_files(source_files):
            continue

        output_path = str(tmp_dir / f"{spec.name}.sarif")
        result = await run_tool(spec, str(source_dir), output_path)

        if not result.success:
            continue

        sarif_path = Path(output_path)
        if not sarif_path.exists() or sarif_path.stat().st_size == 0:
            continue

        try:
            sarif = load_sarif(output_path)
        except Exception:
            continue

        for run in sarif.get("runs", []):
            for r in run.get("results", []):
                rule_id = r.get("ruleId", "")
                locations = r.get("locations", [])
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    # Normalize: strip path prefixes, keep just filename
                    filename = uri.rsplit("/", 1)[-1] if "/" in uri else uri
                    line = phys.get("region", {}).get("startLine", 0)
                    findings.append((rule_id, filename, line))

    return findings
