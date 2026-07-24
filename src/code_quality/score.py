"""score_project — main entry point for PQI scoring."""
from __future__ import annotations

from pathlib import Path

from code_analysis import analyze
from code_analysis.collect import EXCLUDE_DEFAULTS
from code_quality.models import DimensionScore, PQIResult, QualityBand
from code_quality.scoring import (
    compute_pqi,
    score_elegance,
    score_maintainability,
    score_modularity,
    score_reusability,
    score_robustness,
    score_security,
    score_testability,
)
from code_quality.tools import detect_available_tools, run_tools


def score_project(
    target: Path,
    *,
    language: str | None = None,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    profile: str = "production",
    tools: list[str] | None = None,
    include_graph: bool = True,
) -> PQIResult:
    """Score a codebase's quality.

    Args:
        target: Root directory of the codebase.
        language: Language to analyze. None = auto-detect.
        scope: Directory/glob patterns to include.
        exclude: Patterns to exclude.
        profile: Weight profile (production, library, safety_critical).
        tools: Tool names to run. None = auto-detect available.
                Empty list = skip all tools.
        include_graph: Build dependency graph for modularity scoring.

    Returns:
        PQIResult with composite score, dimension breakdown, and quality band.
    """
    languages = [language] if language else None

    # Resolve exclude ONCE and pass the same effective list to analyze() and
    # run_tools(): analyze()->collect_files applies EXCLUDE_DEFAULTS when
    # exclude is None, but the tool runners forward exclude=None as "no
    # excludes at all" — without this, bandit/radon score files the AST
    # dimensions never measured (plan 021 WP-E).
    effective_exclude = list(exclude) if exclude is not None else list(EXCLUDE_DEFAULTS)

    metrics = analyze(
        target,
        scope=scope,
        exclude=effective_exclude,
        languages=languages,
        include_graph=include_graph,
    )

    if not metrics.files:
        return PQIResult(
            composite=0.0,
            quality_band=QualityBand.POOR,
            dimensions={
                "maintainability": DimensionScore(
                    name="Maintainability", score=0.0,
                    recommendations=["No parseable source files found"],
                ),
            },
        )

    if tools is None:
        tools = detect_available_tools()
    tool_results = run_tools(tools, target, scope, effective_exclude) if tools else {}

    dimensions = {
        "maintainability": score_maintainability(metrics, tool_results),
        "security": score_security(metrics, tool_results),
        "modularity": score_modularity(metrics),
        "testability": score_testability(metrics, tool_results),
        "robustness": score_robustness(metrics),
        "elegance": score_elegance(metrics, tool_results),
        "reusability": score_reusability(metrics),
    }

    return compute_pqi(
        dimensions,
        profile=profile,
        file_count=metrics.source_files,
        line_count=metrics.source_lines,
    )
