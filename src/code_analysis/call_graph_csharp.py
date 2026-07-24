"""C# call graph extraction via the Roslyn callgraph tool (tools/roslyn-callgraph).

tree-sitter (used for C# structural metrics elsewhere in code_analysis) has
no type/overload resolution, so it cannot answer "what method does this call
resolve to". Only Roslyn's semantic model can. This module shells out to a
prebuilt Roslyn console tool and parses its JSON output.

Routes subprocess execution through security_review.tools.runner.run_tool_sync
rather than calling subprocess directly, per AGENTS.md's subprocess-isolation
principle (one chokepoint for the whole module, not just security_review).
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from code_analysis.models import CallEdge

logger = structlog.get_logger()

_ROSLYN_TOOL_DIR = Path(__file__).resolve().parent.parent.parent / "tools" / "roslyn-callgraph"
_ROSLYN_TOOL_DLL = _ROSLYN_TOOL_DIR / "bin" / "Debug" / "net8.0" / "roslyn-callgraph.dll"


def _find_roslyn_tool() -> Path | None:
    if _ROSLYN_TOOL_DLL.exists():
        return _ROSLYN_TOOL_DLL
    release_dll = _ROSLYN_TOOL_DIR / "bin" / "Release" / "net8.0" / "roslyn-callgraph.dll"
    if release_dll.exists():
        return release_dll
    return None


def build_csharp_call_edges(root: Path, solution_or_project: Path) -> list[CallEdge]:
    """Extract call edges from C# files using the Roslyn callgraph tool.

    Requires the .NET 8 runtime and a built tools/roslyn-callgraph. The tool
    is optional -- if not found or if it fails, returns an empty list with a
    warning (C# then gets keyword-only file selection, same as before this
    feature existed).
    """
    from code_analysis.store import target_cache_dir
    from security_review.tools.runner import run_tool_sync

    tool_path = _find_roslyn_tool()
    if tool_path is None:
        logger.warning(
            "call_graph.roslyn_tool_not_found",
            hint="Build tools/roslyn-callgraph with 'dotnet build' (see tools/roslyn-callgraph/README)",
        )
        return []

    output_path = target_cache_dir(root) / "roslyn-callgraph.json"

    result = run_tool_sync(
        ["dotnet", str(tool_path), str(solution_or_project), str(output_path)],
        timeout_seconds=300,
        cwd=str(root),
    )
    if result.returncode != 0:
        logger.warning("call_graph.roslyn_tool_error", stderr=result.stderr[:500])
        return []

    if not output_path.exists():
        logger.warning("call_graph.roslyn_tool_no_output")
        return []

    try:
        raw = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logger.warning("call_graph.roslyn_output_invalid", error=str(e))
        return []

    edges: list[CallEdge] = []
    for item in raw:
        kind = "virtual" if item.get("isVirtual") else "direct"
        if item.get("isExtension"):
            kind = "extension"
        edges.append(CallEdge(
            caller=item["caller"],
            callee=item["callee"],
            file_path=item["file"],
            line=item["line"],
            confidence=0.9 if kind == "direct" else 0.7,
            kind=kind,
        ))

    logger.info("call_graph.csharp_edges", count=len(edges))
    return edges
