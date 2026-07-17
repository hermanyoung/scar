"""Build method-level call graphs from source files.

pyan3's only public entry point (create_callgraph) renders to a text format
(dot/svg/tgf/...) and exposes neither per-edge line numbers nor a stable
qualified-name scheme matching this codebase's own SymbolInfo.qualified_name
convention. build_python_call_edges() therefore uses pyan3's internal
CallGraphVisitor directly (uses_edges/module_to_filename) and re-derives each
node's qualified name via path_to_module() -- the same helper the reference
graph builder uses -- so pyan-sourced call edges interoperate with locally
parsed sinks/entry-points on identical qualified names.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import structlog

from code_analysis.graph import path_to_module
from code_analysis.models import CallEdge, CallGraph, ModuleInfo, SymbolInfo
from code_analysis.store import GraphStore

logger = structlog.get_logger()

# pyan3 logs its own AST-visit trace at INFO level via a plain stdlib logger
# (CallGraphVisitor(..., logger=None) -> logging.getLogger(__name__)). Passed
# explicitly here, quieted to WARNING, so it doesn't flood output whenever
# the caller's root logger is at INFO/DEBUG (e.g. scar review --verbose).
_PYAN_LOGGER = logging.getLogger("pyan.analyzer.quiet")
_PYAN_LOGGER.setLevel(logging.WARNING)


def build_python_call_edges(root: Path, python_files: list[Path]) -> list[CallEdge]:
    """Extract call edges from Python files using pyan3's CallGraphVisitor.

    Confidence is uniformly 0.7 (pyan3 exposes no per-edge confidence).
    Line is the *caller's* definition line, not the call site -- pyan3
    aggregates all calls made within a function into one uses-edge set per
    caller, without per-call-site line numbers.
    """
    if not python_files:
        return []

    try:
        from pyan.analyzer import CallGraphVisitor
    except ImportError:
        logger.warning("call_graph.pyan3_not_installed", hint="pip install pyan3>=2.6")
        return []

    abs_paths = [str(f) for f in python_files]
    try:
        visitor = CallGraphVisitor(abs_paths, root=str(root), logger=_PYAN_LOGGER)
    except Exception as e:
        logger.warning("call_graph.pyan3_failed", error=str(e))
        return []

    filename_to_pyan_module = {fn: mod for mod, fn in visitor.module_to_filename.items()}

    def normalise(node) -> tuple[str | None, str | None]:
        """Return (qualified_name, file_path_relative_to_root) or (None, None)."""
        if node.filename is None:
            return None, None
        pyan_module = filename_to_pyan_module.get(node.filename)
        if pyan_module is None:
            return None, None
        try:
            file_rel = str(Path(node.filename).resolve().relative_to(root.resolve()))
        except ValueError:
            return None, None
        our_module = path_to_module(file_rel)

        raw_name = node.get_name()
        prefix = pyan_module + "."
        if raw_name == pyan_module:
            qname = our_module
        elif raw_name.startswith(prefix):
            qname = f"{our_module}.{raw_name[len(prefix):]}"
        else:
            qname = raw_name
        return qname, file_rel

    edges: list[CallEdge] = []
    for caller_node, callee_nodes in visitor.uses_edges.items():
        caller_qname, caller_file = normalise(caller_node)
        if caller_qname is None or caller_file is None:
            continue
        caller_line = getattr(caller_node.ast_node, "lineno", 0) or 0

        for callee_node in callee_nodes:
            callee_qname, _ = normalise(callee_node)
            if callee_qname is not None:
                confidence, kind = 0.7, "direct"
            else:
                # Unresolved (dynamic dispatch, external symbol pyan couldn't
                # bind). Keep the edge -- sinks.yaml patterns like "*.execute"
                # are specifically meant to match these wildcard callees.
                callee_qname = callee_node.get_name()
                confidence, kind = 0.3, "dynamic"

            edges.append(CallEdge(
                caller=caller_qname, callee=callee_qname,
                file_path=caller_file, line=caller_line,
                confidence=confidence, kind=kind,
            ))

    logger.info("call_graph.python_edges", count=len(edges))
    return list(set(edges))


def build_call_graph(
    root: Path,
    modules: list[ModuleInfo],
    *,
    python_files: list[Path] | None = None,
    csharp_solution: Path | None = None,
) -> CallGraph:
    """Build a complete call graph from all available sources.

    1. Extract call edges from pyan3 (Python) and Roslyn (C#)
    2. Merge with existing import/type reference edges from modules
    3. Classify sinks and entry points on locally-defined symbols
    4. Build lookup indexes (file_symbols, symbol_files), unioning in every
       node that appears in a call edge -- even ones with no local
       SymbolInfo (e.g. pyan's unresolved wildcard callees) -- so graph
       walks can always resolve a file for every node they reach.
    """
    from code_analysis.call_graph_csharp import build_csharp_call_edges
    from code_analysis.graph import build_reference_graph
    from code_analysis.sinks import classify_symbol

    ref_graph = build_reference_graph(modules)

    call_edges: list[CallEdge] = []
    if python_files:
        call_edges.extend(build_python_call_edges(root, python_files))
    if csharp_solution:
        call_edges.extend(build_csharp_call_edges(root, csharp_solution))

    for module in modules:
        lang = module.language
        for cls in module.classes:
            classify_symbol(cls, lang)
            for method in cls.methods:
                classify_symbol(method, lang)
        for func in module.functions:
            classify_symbol(func, lang)

    all_symbols: list[str] = []
    file_symbols: dict[str, list[str]] = {}
    symbol_files: dict[str, str] = {}
    entry_points: list[str] = []
    sinks: dict[str, list[str]] = {}

    for module in modules:
        for cls in module.classes:
            _index_symbol(cls, module.path, all_symbols, file_symbols, symbol_files, entry_points, sinks)
            for method in cls.methods:
                _index_symbol(method, module.path, all_symbols, file_symbols, symbol_files, entry_points, sinks)
        for func in module.functions:
            _index_symbol(func, module.path, all_symbols, file_symbols, symbol_files, entry_points, sinks)

    # Union in every call-edge endpoint too, so walks can resolve files for
    # nodes that only exist in the call graph (e.g. pyan's own module-level
    # node, or a symbol whose defining file wasn't itself part of `modules`).
    for edge in call_edges:
        if edge.caller not in symbol_files:
            symbol_files[edge.caller] = edge.file_path
            file_symbols.setdefault(edge.file_path, []).append(edge.caller)
            all_symbols.append(edge.caller)

    nodes = sorted(set(all_symbols) | set(ref_graph.nodes))

    return CallGraph(
        nodes=nodes,
        call_edges=list(set(call_edges)),
        reference_edges=ref_graph.edges,
        entry_points=entry_points,
        sinks=sinks,
        file_symbols=file_symbols,
        symbol_files=symbol_files,
    )


def _index_symbol(
    symbol: SymbolInfo,
    file_path: str,
    all_symbols: list[str],
    file_symbols: dict[str, list[str]],
    symbol_files: dict[str, str],
    entry_points: list[str],
    sinks: dict[str, list[str]],
) -> None:
    qn = symbol.qualified_name
    all_symbols.append(qn)
    file_symbols.setdefault(file_path, []).append(qn)
    symbol_files[qn] = file_path
    if symbol.is_entry_point:
        entry_points.append(qn)
    if symbol.is_sink:
        sinks[qn] = symbol.cwe_tags


def build_call_graph_incremental(
    root: Path,
    modules: list[ModuleInfo],
    store: GraphStore,
    *,
    python_files: list[Path] | None = None,
    csharp_solution: Path | None = None,
) -> CallGraph:
    """Build the call graph, reusing cached data for unchanged files.

    1. Compute SHA-256 for each source file
    2. Ask the store which files changed (new, modified, or deleted)
    3. Re-parse and re-classify only the changed files
    4. Update the store with new symbols and edges
    5. Load the full graph from the store

    C# edges are re-extracted in full whenever any C# file changed --
    Roslyn's semantic model needs the whole solution loaded to resolve
    cross-file symbols, so there is no cheaper per-file alternative.
    """
    from code_analysis.call_graph_csharp import build_csharp_call_edges
    from code_analysis.sinks import classify_symbol

    file_shas: dict[str, str] = {}
    for module in modules:
        full_path = root / module.path
        if full_path.exists():
            file_shas[module.path] = hashlib.sha256(full_path.read_bytes()).hexdigest()

    changed = store.get_changed_files(file_shas)
    if not changed:
        logger.info("call_graph.incremental", changed=0, cached="all")
        return store.load_call_graph()

    logger.info("call_graph.incremental", changed=len(changed), total=len(file_shas))

    changed_modules = [m for m in modules if m.path in changed]
    changed_paths = {m.path for m in changed_modules}

    changed_py = [root / m.path for m in changed_modules if m.language == "python"]
    py_edges = build_python_call_edges(root, changed_py) if changed_py else []

    cs_edges: list[CallEdge] = []
    if csharp_solution and any(m.language == "csharp" for m in changed_modules):
        cs_edges = build_csharp_call_edges(root, csharp_solution)
        # Roslyn re-extracts the whole solution -- keep only edges for
        # changed files, since unchanged files' edges are already cached.
        cs_edges = [e for e in cs_edges if e.file_path in changed_paths]

    for module in changed_modules:
        store.delete_file_data(module.path)

        for cls in module.classes:
            classify_symbol(cls, module.language)
            for method in cls.methods:
                classify_symbol(method, module.language)
        for func in module.functions:
            classify_symbol(func, module.language)

        symbols_data = _module_to_symbol_dicts(module)
        file_edges = [e for e in py_edges + cs_edges if e.file_path == module.path]

        # file_cache row must exist before symbols/call_edges are inserted --
        # symbols.file_path is a foreign key into file_cache(file_path).
        store.upsert_file(module.path, file_shas[module.path], module.language,
                          len(symbols_data), len(file_edges))
        store.insert_symbols(symbols_data)
        store.insert_call_edges(file_edges)

    store.commit()
    return store.load_call_graph()


def _module_to_symbol_dicts(module: ModuleInfo) -> list[dict]:
    """Flatten a ModuleInfo's classes/methods/functions into GraphStore.insert_symbols() rows."""
    rows: list[dict] = []

    def _row(symbol: SymbolInfo, kind: str) -> dict:
        return {
            "qualified_name": symbol.qualified_name, "file_path": module.path, "kind": kind,
            "line_number": symbol.line, "end_line": symbol.end_line,
            "is_entry_point": symbol.is_entry_point, "is_sink": symbol.is_sink,
            "cwe_tags": symbol.cwe_tags, "decorators": symbol.decorators,
        }

    for cls in module.classes:
        rows.append(_row(cls, "class"))
        for method in cls.methods:
            rows.append(_row(method, "method"))
    for func in module.functions:
        rows.append(_row(func, "function"))
    return rows
