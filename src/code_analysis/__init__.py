"""Code Analysis — structural analysis with pluggable language parsers.

Public API:
    analyze()        — Analyze a codebase, returns ProjectMetrics
    collect_files()  — Discover source files
    get_parser()     — Get a parser by language name
    list_languages() — List available parsers
"""

from __future__ import annotations

import structlog

import code_analysis.parsers.python  # noqa: F401  (side-effect: register Python parser)
from code_analysis.analysis import analyze
from code_analysis.call_graph import build_call_graph
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
from code_analysis.paths import MODULE_ROOT

logger = structlog.get_logger()

# Import the C# parser to trigger registration; tree-sitter may be absent.
try:
    import code_analysis.parsers.csharp  # noqa: F401
except ValueError:
    logger.warning("code_analysis.csharp_parser_unavailable", reason="tree-sitter not installed")

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
