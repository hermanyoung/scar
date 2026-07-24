"""Code Analysis — structural analysis with pluggable language parsers.

Public API:
    analyze()        — Analyze a codebase, returns ProjectMetrics
    collect_files()  — Discover source files
    get_parser()     — Get a parser by language name
    list_languages() — List available parsers
"""

from __future__ import annotations

from pathlib import Path

import structlog

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

logger = structlog.get_logger()


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
    logger.warning("code_analysis.csharp_parser_unavailable", reason="tree-sitter not installed")

from code_analysis.analysis import analyze  # noqa: E402
from code_analysis.call_graph import build_call_graph  # noqa: E402

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
