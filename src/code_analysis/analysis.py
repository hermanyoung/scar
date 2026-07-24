"""Top-level `analyze()` entry point — parses files, classifies test vs.
source, and optionally builds the reference graph.

Split out of code_analysis/__init__.py (plan 021 WP-H) to keep the package
init file to registration/bootstrap only, per P10 (modular, single
responsibility).
"""

from __future__ import annotations

from pathlib import Path

from code_analysis.collect import collect_files
from code_analysis.graph import build_reference_graph, compute_pagerank
from code_analysis.models import FileMetrics, ModuleInfo, ProjectMetrics
from code_analysis.parsers import get_parser, get_parser_for_extension


def analyze(
    target: Path,
    *,
    files: list[Path] | None = None,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    languages: list[str] | None = None,
    include_graph: bool = False,
) -> ProjectMetrics:
    """Analyze a codebase. Main entry point.

    Args:
        target: Root directory of the codebase.
        files: Pre-discovered file list (skips collection if provided).
        scope: Directory/glob patterns to include (used when files is None).
        exclude: Patterns to skip (used when files is None).
        languages: Filter to specific languages. None = all available.
        include_graph: Build reference graph and compute PageRank.

    Returns:
        ProjectMetrics with per-file metrics and optional graph data.
    """
    if files is None:
        # Determine which extensions to collect
        if languages:
            extensions: set[str] = set()
            for lang in languages:
                parser = get_parser(lang)
                extensions.update(parser.extensions)
        else:
            extensions = None  # type: ignore[assignment]

        files = collect_files(target, scope=scope, exclude=exclude, extensions=extensions)

    # Parse each file with the appropriate parser
    all_metrics: list[FileMetrics] = []
    all_modules: list[ModuleInfo] = []
    test_files = 0
    test_lines = 0
    source_files = 0
    source_lines = 0

    for file_path in files:
        parser = get_parser_for_extension(file_path.suffix)
        if parser is None:
            continue

        # Apply language filter
        if languages and parser.language not in languages:
            continue

        rel_path = str(file_path.relative_to(target)).replace("\\", "/")
        result = parser.analyze_file(file_path, rel_path, include_structure=include_graph)
        if result is None:
            continue

        all_metrics.append(result.metrics)
        if result.module is not None:
            all_modules.append(result.module)

        # Classify as test or source
        is_test = _is_test_file(rel_path)
        if is_test:
            test_files += 1
            test_lines += result.metrics.lines
        else:
            source_files += 1
            source_lines += result.metrics.lines

    # Build graph if requested
    graph = None
    ranks: dict[str, float] = {}
    if include_graph and all_modules:
        graph = build_reference_graph(all_modules)
        ranks = compute_pagerank(graph)

    return ProjectMetrics(
        files=all_metrics,
        modules=all_modules,
        graph=graph,
        ranks=ranks,
        test_files=test_files,
        test_lines=test_lines,
        source_files=source_files,
        source_lines=source_lines,
    )


def _is_test_file(rel_path: str) -> bool:
    """Heuristic: is this file part of a test suite?"""
    parts = rel_path.split("/")
    return (
        "tests" in parts
        or "test" in parts
        or any(p.startswith("test_") for p in parts)
        or rel_path.startswith("tests/")
        or rel_path.startswith("test_")
    )
