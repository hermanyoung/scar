"""Cross-reference graph construction and PageRank computation."""

from __future__ import annotations

from collections import defaultdict

from code_analysis.models import ModuleInfo, ReferenceEdge, ReferenceGraph, SymbolInfo


def build_reference_graph(modules: list[ModuleInfo]) -> ReferenceGraph:
    """Build a dependency graph from module structural data."""
    known_modules = _build_module_index(modules)
    known_symbols = _build_symbol_index(modules)
    import_tables = _build_import_tables(modules, known_modules)

    nodes = sorted(known_modules | known_symbols.keys())
    edges: list[ReferenceEdge] = []

    for module in modules:
        module_qname = _path_to_module(module.path)

        for imp in module.imports:
            target = _resolve_import(imp, known_modules)
            if target:
                edges.append(ReferenceEdge(source=module_qname, target=target))

        for cls in module.classes:
            for base in cls.bases:
                target = _resolve_name(base, module_qname, import_tables, known_symbols)
                if target:
                    edges.append(ReferenceEdge(source=cls.qualified_name, target=target))
            for method in cls.methods:
                _add_symbol_references(method, module_qname, import_tables, known_symbols, edges)

        for func in module.functions:
            _add_symbol_references(func, module_qname, import_tables, known_symbols, edges)

    return ReferenceGraph(nodes=nodes, edges=list(set(edges)))


def compute_pagerank(
    graph: ReferenceGraph,
    damping: float = 0.85,
    max_iterations: int = 100,
    tolerance: float = 1e-6,
) -> dict[str, float]:
    """Compute PageRank scores for all nodes in the graph.

    Returns normalized scores (0.0-1.0) where 1.0 is the highest-rank node.
    """
    if not graph.nodes:
        return {}

    n = len(graph.nodes)
    node_index = {name: i for i, name in enumerate(graph.nodes)}
    outgoing: dict[int, list[int]] = defaultdict(list)
    incoming: dict[int, list[int]] = defaultdict(list)

    for edge in graph.edges:
        src_idx = node_index.get(edge.source)
        tgt_idx = node_index.get(edge.target)
        if src_idx is not None and tgt_idx is not None and src_idx != tgt_idx:
            outgoing[src_idx].append(tgt_idx)
            incoming[tgt_idx].append(src_idx)

    scores = [1.0 / n] * n
    teleport = (1.0 - damping) / n

    for _ in range(max_iterations):
        new_scores = [0.0] * n
        dangling_sum = sum(scores[i] for i in range(n) if not outgoing[i])
        dangling_contribution = damping * dangling_sum / n

        for i in range(n):
            rank_sum = sum(scores[src] / len(outgoing[src]) for src in incoming[i])
            new_scores[i] = teleport + dangling_contribution + damping * rank_sum

        delta = sum(abs(new_scores[i] - scores[i]) for i in range(n))
        scores = new_scores
        if delta < tolerance:
            break

    max_score = max(scores) if scores else 1.0
    if max_score > 0:
        scores = [s / max_score for s in scores]

    return {graph.nodes[i]: scores[i] for i in range(n)}


# -- Internal helpers --------------------------------------------------------


def _path_to_module(rel_path: str) -> str:
    module = rel_path.replace("/", ".").replace("\\", ".")
    if module.endswith(".py"):
        module = module[:-3]
    elif module.endswith(".cs"):
        module = module[:-3]
    if module.endswith(".__init__"):
        module = module[:-9]
    if module.startswith("src."):
        module = module[4:]
    return module


def _build_module_index(modules: list[ModuleInfo]) -> set[str]:
    index: set[str] = set()
    for module in modules:
        qname = _path_to_module(module.path)
        index.add(qname)
        parts = qname.split(".")
        for i in range(1, len(parts)):
            index.add(".".join(parts[:i]))
    return index


def _build_symbol_index(modules: list[ModuleInfo]) -> dict[str, str]:
    index: dict[str, str] = {}
    for module in modules:
        for cls in module.classes:
            index[cls.qualified_name] = cls.name
            for method in cls.methods:
                index[method.qualified_name] = method.name
        for func in module.functions:
            index[func.qualified_name] = func.name
    return index


def _build_import_tables(
    modules: list[ModuleInfo], known_modules: set[str],
) -> dict[str, dict[str, str]]:
    tables: dict[str, dict[str, str]] = {}
    for module in modules:
        module_qname = _path_to_module(module.path)
        table: dict[str, str] = {}
        for imp in module.imports:
            resolved = _resolve_import(imp, known_modules)
            if resolved:
                table[imp.rsplit(".", 1)[-1]] = resolved
        tables[module_qname] = table
    return tables


def _resolve_import(imp: str, known_modules: set[str]) -> str | None:
    if imp in known_modules:
        return imp
    parent = imp.rsplit(".", 1)[0] if "." in imp else None
    if parent and parent in known_modules:
        return parent
    return None


def _resolve_name(
    name: str,
    module_qname: str,
    import_tables: dict[str, dict[str, str]],
    known_symbols: dict[str, str],
) -> str | None:
    name = _strip_generics(name)
    if not name or name[0].islower():
        return None
    table = import_tables.get(module_qname, {})
    if name in table:
        return table[name]
    for qname in known_symbols:
        if qname.endswith(f".{name}"):
            return qname
    return None


def _strip_generics(type_str: str) -> str:
    if " | " in type_str:
        parts = [p.strip() for p in type_str.split(" | ") if p.strip() != "None"]
        return _strip_generics(parts[0]) if parts else ""
    if "[" in type_str and "]" in type_str:
        return type_str[:type_str.index("[")]
    if "<" in type_str and ">" in type_str:
        return type_str[:type_str.index("<")]
    return type_str


def _add_symbol_references(
    symbol: SymbolInfo,
    module_qname: str,
    import_tables: dict[str, dict[str, str]],
    known_symbols: dict[str, str],
    edges: list[ReferenceEdge],
) -> None:
    for param in symbol.params:
        if ": " in param:
            type_str = param.split(": ", 1)[1]
            target = _resolve_name(type_str, module_qname, import_tables, known_symbols)
            if target:
                edges.append(ReferenceEdge(source=symbol.qualified_name, target=target))
    if symbol.return_type:
        target = _resolve_name(symbol.return_type, module_qname, import_tables, known_symbols)
        if target:
            edges.append(ReferenceEdge(source=symbol.qualified_name, target=target))
