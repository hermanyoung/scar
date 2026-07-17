"""Code Analysis — structural analysis with pluggable language parsers.

Public API:
    analyze()        — Analyze a codebase, returns ProjectMetrics
    collect_files()  — Discover source files
    get_parser()     — Get a parser by language name
    list_languages() — List available parsers
"""

from __future__ import annotations

from pathlib import Path

from code_analysis.collect import collect_files
from code_analysis.graph import build_reference_graph, compute_call_graph_pagerank, compute_pagerank
from code_analysis.models import (
    CallEdge,
    CallGraph,
    FileMetrics,
    FileResult,
    ModuleInfo,
    ProjectMetrics,
    ReferenceGraph,
    SymbolInfo,
    SymbolKind,
)
from code_analysis.parsers import get_parser, get_parser_for_extension, list_languages


def _find_project_root() -> Path:
    """Walk up from this file to find the directory containing .project_root.

    WARNING: This is intentionally duplicated from security_review/__init__.py
    and scar.py -- code_analysis must resolve config paths without depending
    on the security_review package (it is also used standalone by code_quality).
    """
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / ".project_root").exists():
            return parent
    raise RuntimeError(
        "Cannot find .project_root marker. "
        "Ensure .project_root exists at the repository root."
    )


# Canonical project root -- used to locate config/taxonomy/sinks.yaml.
MODULE_ROOT = _find_project_root()

# Import parsers to trigger registration
import code_analysis.parsers.python  # noqa: F401

try:
    import code_analysis.parsers.csharp  # noqa: F401
except ValueError:
    pass  # tree-sitter not installed — C# parser unavailable

from code_analysis.call_graph import build_call_graph  # noqa: E402


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


__all__ = [
    "analyze",
    "build_call_graph",
    "collect_files",
    "compute_call_graph_pagerank",
    "compute_pagerank",
    "get_parser",
    "list_languages",
    "CallEdge",
    "CallGraph",
    "FileMetrics",
    "FileResult",
    "ModuleInfo",
    "ProjectMetrics",
    "ReferenceGraph",
    "SymbolInfo",
    "SymbolKind",
]
