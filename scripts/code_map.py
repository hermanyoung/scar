#!/usr/bin/env python3
"""Generate a structural code map of the repository.

Produces a JSON or Markdown representation of the codebase's structure,
ranked by PageRank importance. Output can be piped to an LLM or saved
as an artifact.

Usage:
    python scripts/code_map.py                          # Markdown to .codemap/map.md
    python scripts/code_map.py --stdout                 # Markdown to stdout
    python scripts/code_map.py --format json --pretty   # Pretty-printed JSON
    python scripts/code_map.py --max-tokens 2048        # Token-budgeted
    python scripts/code_map.py --stats                  # Summary statistics only
    python scripts/code_map.py --scope src/ scripts/ --exclude ""  # Custom scope
"""

from __future__ import annotations

import argparse
import ast
import copy
import datetime
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# -- Types -------------------------------------------------------------------


class SymbolKind(str, Enum):
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    CONSTANT = "constant"


@dataclass
class SymbolInfo:
    name: str
    kind: SymbolKind
    qualified_name: str
    line: int
    end_line: int = 0
    params: list[str] = field(default_factory=list)
    return_type: str = ""
    bases: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    methods: list["SymbolInfo"] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)


@dataclass
class ModuleInfo:
    path: str
    lines: int
    imports: list[str]
    classes: list[SymbolInfo]
    functions: list[SymbolInfo]
    constants: list[str]
    references: list[str]


@dataclass
class ReferenceEdge:
    source: str
    target: str

    def __hash__(self) -> int:
        return hash((self.source, self.target))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ReferenceEdge):
            return NotImplemented
        return self.source == other.source and self.target == other.target


@dataclass
class ReferenceGraph:
    nodes: list[str]
    edges: list[ReferenceEdge]


# -- Stage 1: Parse ---------------------------------------------------------


def parse_modules(
    repo_root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[ModuleInfo]:
    files = _collect_files(repo_root, scope, exclude)
    modules: list[ModuleInfo] = []
    for file_path in sorted(files):
        module = _parse_file(repo_root, file_path)
        if module is not None:
            modules.append(module)
    return modules


def _collect_files(
    repo_root: Path,
    scope: list[str] | None,
    exclude: list[str] | None,
) -> list[Path]:
    exclude = exclude or []
    exclude_set = set(exclude)

    if scope:
        files: list[Path] = []
        for pattern in scope:
            if pattern.endswith("/"):
                files.extend(repo_root.glob(f"{pattern}**/*.py"))
            elif "*" in pattern:
                files.extend(repo_root.glob(pattern))
            else:
                candidate = repo_root / pattern
                if candidate.is_file() and candidate.suffix == ".py":
                    files.append(candidate)
                elif candidate.is_dir():
                    files.extend(candidate.rglob("*.py"))
        files = list(set(files))
    else:
        files = list(repo_root.rglob("*.py"))

    result = []
    for f in files:
        rel = str(f.relative_to(repo_root))
        if any(_matches_exclude(rel, exc) for exc in exclude_set):
            continue
        result.append(f)
    return result


def _matches_exclude(rel_path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return rel_path.startswith(pattern) or rel_path.startswith(pattern.rstrip("/"))
    if "*" in pattern or "?" in pattern or "[" in pattern:
        from fnmatch import fnmatch
        return fnmatch(rel_path, pattern)
    return rel_path.startswith(pattern)


def _parse_file(repo_root: Path, file_path: Path) -> ModuleInfo | None:
    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return None

    rel_path = str(file_path.relative_to(repo_root))
    line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)

    imports = _extract_imports(tree)
    classes = _extract_classes(tree, rel_path)
    functions = _extract_functions(tree, rel_path)
    constants = _extract_constants(tree)
    references = _extract_references(tree)

    return ModuleInfo(
        path=rel_path,
        lines=line_count,
        imports=imports,
        classes=classes,
        functions=functions,
        constants=constants,
        references=references,
    )


def _extract_imports(tree: ast.Module) -> list[str]:
    imports: list[str] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def _extract_classes(tree: ast.Module, module_path: str) -> list[SymbolInfo]:
    classes: list[SymbolInfo] = []
    module_qname = _path_to_module(module_path)
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            classes.append(_parse_class(node, module_qname))
    return classes


def _parse_class(node: ast.ClassDef, module_qname: str) -> SymbolInfo:
    bases = [_name_from_node(b) for b in node.bases if _name_from_node(b)]
    decorators = [_name_from_node(d) for d in node.decorator_list if _name_from_node(d)]
    class_qname = f"{module_qname}.{node.name}"

    fields: list[str] = []
    methods: list[SymbolInfo] = []

    for item in ast.iter_child_nodes(node):
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            annotation = _annotation_str(item.annotation)
            fields.append(f"{item.target.id}: {annotation}")
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.append(_parse_function(item, class_qname, is_method=True))

    return SymbolInfo(
        name=node.name,
        kind=SymbolKind.CLASS,
        qualified_name=class_qname,
        line=node.lineno,
        end_line=node.end_lineno or node.lineno,
        bases=bases,
        fields=fields,
        methods=methods,
        decorators=decorators,
    )


def _extract_functions(tree: ast.Module, module_path: str) -> list[SymbolInfo]:
    functions: list[SymbolInfo] = []
    module_qname = _path_to_module(module_path)
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(_parse_function(node, module_qname, is_method=False))
    return functions


def _parse_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_qname: str,
    is_method: bool,
) -> SymbolInfo:
    params: list[str] = []
    for arg in node.args.args:
        if is_method and arg.arg in ("self", "cls"):
            continue
        annotation = _annotation_str(arg.annotation) if arg.annotation else ""
        param_str = f"{arg.arg}: {annotation}" if annotation else arg.arg
        params.append(param_str)

    return_type = _annotation_str(node.returns) if node.returns else ""
    decorators = [_name_from_node(d) for d in node.decorator_list if _name_from_node(d)]

    return SymbolInfo(
        name=node.name,
        kind=SymbolKind.METHOD if is_method else SymbolKind.FUNCTION,
        qualified_name=f"{parent_qname}.{node.name}",
        line=node.lineno,
        end_line=node.end_lineno or node.lineno,
        params=params,
        return_type=return_type,
        decorators=decorators,
    )


def _extract_constants(tree: ast.Module) -> list[str]:
    constants: list[str] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            if name.isupper() or (name.startswith("_") and name[1:].isupper()):
                annotation = _annotation_str(node.annotation)
                constants.append(f"{name}: {annotation}")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    constants.append(target.id)
    return constants


def _extract_references(tree: ast.Module) -> list[str]:
    refs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            refs.add(node.id)
        elif isinstance(node, ast.Attribute):
            chain = _attribute_chain(node)
            if chain:
                refs.add(chain)
    return sorted(refs)


def _attribute_chain(node: ast.Attribute) -> str:
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _annotation_str(node: ast.expr | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _attribute_chain(node)
    if isinstance(node, ast.Subscript):
        value = _annotation_str(node.value)
        slice_str = _annotation_str(node.slice)
        return f"{value}[{slice_str}]"
    if isinstance(node, ast.Tuple):
        elts = ", ".join(_annotation_str(e) for e in node.elts)
        return elts
    if isinstance(node, ast.List):
        elts = ", ".join(_annotation_str(e) for e in node.elts)
        return f"[{elts}]"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _annotation_str(node.left)
        right = _annotation_str(node.right)
        return f"{left} | {right}"
    return ast.dump(node)


def _name_from_node(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _attribute_chain(node)
    if isinstance(node, ast.Call):
        return _name_from_node(node.func)
    return ""


def _path_to_module(rel_path: str) -> str:
    module = rel_path.replace("/", ".").replace("\\", ".")
    if module.endswith(".py"):
        module = module[:-3]
    if module.endswith(".__init__"):
        module = module[:-9]
    # Strip src. prefix so qnames match import strings (src/security_review/ -> security_review)
    if module.startswith("src."):
        module = module[4:]
    return module


# -- Stage 2: Build Cross-Reference Graph -----------------------------------


def build_reference_graph(modules: list[ModuleInfo]) -> ReferenceGraph:
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

            for field_str in cls.fields:
                if ": " in field_str:
                    type_str = field_str.split(": ", 1)[1]
                    target = _resolve_name(type_str, module_qname, import_tables, known_symbols)
                    if target:
                        edges.append(ReferenceEdge(source=cls.qualified_name, target=target))

        for func in module.functions:
            _add_symbol_references(func, module_qname, import_tables, known_symbols, edges)

    unique_edges = list(set(edges))
    return ReferenceGraph(nodes=nodes, edges=unique_edges)


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
    modules: list[ModuleInfo],
    known_modules: set[str],
) -> dict[str, dict[str, str]]:
    tables: dict[str, dict[str, str]] = {}
    for module in modules:
        module_qname = _path_to_module(module.path)
        table: dict[str, str] = {}
        for imp in module.imports:
            resolved = _resolve_import(imp, known_modules)
            if resolved:
                short = imp.rsplit(".", 1)[-1]
                table[short] = resolved
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
        if parts:
            return _strip_generics(parts[0])
        return ""

    if "[" in type_str and "]" in type_str:
        inner = type_str[type_str.index("[") + 1 : type_str.rindex("]")]
        parts = _split_type_args(inner)
        for part in reversed(parts):
            stripped = part.strip()
            if stripped and stripped[0].isupper():
                return stripped
        return ""

    return type_str


def _split_type_args(args_str: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in args_str:
        if char == "[":
            depth += 1
            current.append(char)
        elif char == "]":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current))
    return parts


# -- Stage 3: PageRank ------------------------------------------------------


def rank_symbols(
    graph: ReferenceGraph,
    damping: float = 0.85,
    max_iterations: int = 100,
    tolerance: float = 1e-6,
) -> dict[str, float]:
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
            rank_sum = sum(
                scores[src] / len(outgoing[src])
                for src in incoming[i]
            )
            new_scores[i] = teleport + dangling_contribution + damping * rank_sum

        delta = sum(abs(new_scores[i] - scores[i]) for i in range(n))
        scores = new_scores
        if delta < tolerance:
            break

    max_score = max(scores) if scores else 1.0
    if max_score > 0:
        scores = [s / max_score for s in scores]

    return {graph.nodes[i]: scores[i] for i in range(n)}


# -- Stage 4: Assemble ------------------------------------------------------


def assemble_code_map(
    modules: list[ModuleInfo],
    ranks: dict[str, float],
    repo_root_name: str = "",
    commit: str = "",
) -> dict:
    modules_dict: dict[str, dict] = {}
    import_graph: dict[str, list[str]] = {}
    internal_modules = {_path_to_module(m.path) for m in modules}

    for module in modules:
        module_qname = _path_to_module(module.path)
        module_rank = ranks.get(module_qname, 0.0)

        classes_dict: dict[str, dict] = {}
        for cls in module.classes:
            methods_list = [
                f"{m.name}({', '.join(m.params)}) -> {m.return_type}"
                if m.return_type else f"{m.name}({', '.join(m.params)})"
                for m in cls.methods
            ]
            classes_dict[cls.name] = {
                "bases": cls.bases,
                "fields": cls.fields,
                "methods": methods_list,
                "rank": round(ranks.get(cls.qualified_name, 0.0), 4),
            }

        functions_dict: dict[str, dict] = {}
        for func in module.functions:
            functions_dict[func.name] = {
                "params": func.params,
                "returns": func.return_type,
                "decorators": func.decorators,
                "rank": round(ranks.get(func.qualified_name, 0.0), 4),
            }

        modules_dict[module.path] = {
            "lines": module.lines,
            "rank": round(module_rank, 4),
            "imports": module.imports,
            "classes": classes_dict,
            "functions": functions_dict,
            "constants": module.constants,
        }

        internal_imports = [
            imp for imp in module.imports
            if _is_internal_import(imp, internal_modules)
        ]
        if internal_imports:
            import_graph[module_qname] = internal_imports

    total_classes = sum(len(m.classes) for m in modules)
    total_functions = sum(len(m.functions) for m in modules)

    return {
        "project_id": repo_root_name,
        "commit": commit,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "generator_version": "1.0.0",
        "modules": modules_dict,
        "import_graph": import_graph,
        "stats": {
            "total_files": len(modules),
            "total_lines": sum(m.lines for m in modules),
            "total_classes": total_classes,
            "total_functions": total_functions,
        },
    }


def trim_by_rank(code_map: dict, max_tokens: int = 4096) -> dict:
    trimmed = copy.deepcopy(code_map)
    current_tokens = _estimate_tokens(trimmed)

    if current_tokens <= max_tokens:
        return trimmed

    all_symbols = _collect_ranked_symbols(trimmed)
    all_symbols.sort(key=lambda x: x[1])

    for path, rank, kind, name, parent in all_symbols:
        if _estimate_tokens(trimmed) <= max_tokens:
            break
        _remove_symbol(trimmed, path, kind, name, parent)

    if _estimate_tokens(trimmed) <= max_tokens:
        return trimmed

    for path, mod in list(trimmed["modules"].items()):
        for cls_name, cls_data in mod.get("classes", {}).items():
            cls_data["methods"] = [
                m for m in cls_data["methods"] if not _method_name(m).startswith("_")
            ]

    if _estimate_tokens(trimmed) <= max_tokens:
        return trimmed

    for mod in trimmed["modules"].values():
        mod["constants"] = []

    if _estimate_tokens(trimmed) <= max_tokens:
        return trimmed

    for mod in trimmed["modules"].values():
        mod["imports"] = []

    if _estimate_tokens(trimmed) <= max_tokens:
        return trimmed

    trimmed["modules"] = {
        p: m for p, m in trimmed["modules"].items() if m["lines"] >= 20
    }

    if _estimate_tokens(trimmed) <= max_tokens:
        return trimmed

    ranked_modules = sorted(
        trimmed["modules"].items(), key=lambda x: x[1]["rank"],
    )
    while _estimate_tokens(trimmed) > max_tokens and ranked_modules:
        path, _ = ranked_modules.pop(0)
        del trimmed["modules"][path]

    return trimmed


def render_markdown_tree(code_map: dict) -> str:
    lines: list[str] = []

    lines.append(f"# Code Map -- {code_map.get('project_id', 'unknown')}")
    lines.append("")
    stats = code_map.get("stats", {})
    commit = code_map.get("commit", "")
    commit_short = commit[:12] if commit else "unknown"
    lines.append(
        f"**{stats.get('total_files', 0)} files** | "
        f"**{stats.get('total_lines', 0):,} lines** | "
        f"**{stats.get('total_classes', 0)} classes** | "
        f"**{stats.get('total_functions', 0)} functions** | "
        f"commit `{commit_short}`"
    )
    lines.append("")
    lines.append("Symbols ranked by PageRank (most-connected first).")
    lines.append("")

    import_graph = code_map.get("import_graph", {})
    if import_graph:
        circular = find_circular_deps(import_graph)
        lines.append("## Dependencies")
        lines.append("")
        if circular:
            lines.append(f"**Circular dependencies ({len(circular)}):**")
            for cycle in circular:
                lines.append(f"  ! {' -> '.join(cycle)}")
            lines.append("")
        sorted_deps = sorted(
            import_graph.items(),
            key=lambda x: len(x[1]),
            reverse=True,
        )
        circular_edges: set[tuple[str, str]] = set()
        for cycle in circular:
            for i in range(len(cycle) - 1):
                circular_edges.add((cycle[i], cycle[i + 1]))
        for module, deps in sorted_deps:
            dep_strs = []
            for d in deps:
                short_d = d
                if (module, d) in circular_edges:
                    short_d += " [circular]"
                dep_strs.append(short_d)
            lines.append(f"  {module} -> {', '.join(dep_strs)}")
        lines.append("")

    sorted_modules = sorted(
        code_map.get("modules", {}).items(),
        key=lambda x: x[1].get("rank", 0),
        reverse=True,
    )

    layers: dict[str, list[tuple[str, dict]]] = {}
    for path, mod in sorted_modules:
        layer = _get_layer(path)
        layers.setdefault(layer, []).append((path, mod))

    sorted_layers = sorted(
        layers.items(),
        key=lambda x: sum(m.get("rank", 0) for _, m in x[1]),
        reverse=True,
    )

    for layer_name, layer_modules in sorted_layers:
        lines.append(f"## {layer_name}")
        lines.append("")
        for path, mod in layer_modules:
            _render_module(lines, path, mod)
        lines.append("")

    return "\n".join(lines)


def render_for_agent(code_map: dict, max_tokens: int = 4096) -> str:
    rendered = render_markdown_tree(code_map)
    if _estimate_tokens(rendered) <= max_tokens:
        return rendered

    working = copy.deepcopy(code_map)
    ranked_modules = sorted(
        working["modules"].items(),
        key=lambda x: x[1].get("rank", 0),
    )

    for path, _ in ranked_modules:
        del working["modules"][path]
        rendered = render_markdown_tree(working)
        if _estimate_tokens(rendered) <= max_tokens:
            return rendered

    return rendered


def _render_module(lines: list[str], path: str, mod: dict) -> None:
    line_count = mod.get("lines", 0)
    lines.append(f"{path} ({line_count} lines):")

    sorted_classes = sorted(
        mod.get("classes", {}).items(),
        key=lambda x: x[1].get("rank", 0),
        reverse=True,
    )

    for cls_name, cls_data in sorted_classes:
        bases_str = f"({', '.join(cls_data.get('bases', []))})" if cls_data.get("bases") else ""
        lines.append(f"\u2502class {cls_name}{bases_str}:")

        for fld in cls_data.get("fields", []):
            lines.append(f"\u2502    {fld}")

        for method_sig in cls_data.get("methods", []):
            lines.append(f"\u2502    def {method_sig}")

    sorted_functions = sorted(
        mod.get("functions", {}).items(),
        key=lambda x: x[1].get("rank", 0),
        reverse=True,
    )

    for func_name, func_data in sorted_functions:
        params = func_data.get("params", [])
        params_str = ", ".join(params[:3])
        if len(params) > 3:
            params_str += ", ..."
        returns = func_data.get("returns", "")
        ret_str = f" -> {returns}" if returns else ""
        decorators = func_data.get("decorators", [])
        for dec in decorators:
            lines.append(f"\u2502@{dec}")
        lines.append(f"\u2502def {func_name}({params_str}){ret_str}")

    lines.append("")


def find_circular_deps(import_graph: dict[str, list[str]]) -> list[list[str]]:
    visited: set[str] = set()
    in_stack: set[str] = set()
    stack: list[str] = []
    cycles: list[list[str]] = []

    def _dfs(node: str) -> None:
        if node in in_stack:
            cycle_start = stack.index(node)
            cycle = stack[cycle_start:] + [node]
            cycles.append(cycle)
            return
        if node in visited:
            return
        visited.add(node)
        in_stack.add(node)
        stack.append(node)
        for dep in import_graph.get(node, []):
            _dfs(dep)
        stack.pop()
        in_stack.remove(node)

    for node in import_graph:
        if node not in visited:
            _dfs(node)

    return cycles


def _get_layer(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 3:
        return parts[1] if len(parts[0]) > 0 else parts[0]
    if len(parts) == 2:
        return parts[0]
    return "root"


def _estimate_tokens(data: dict | str) -> int:
    if isinstance(data, str):
        text = data
    else:
        text = json.dumps(data)
    return len(text) // 4


def _collect_ranked_symbols(
    code_map: dict,
) -> list[tuple[str, float, str, str, str | None]]:
    symbols: list[tuple[str, float, str, str, str | None]] = []
    for path, mod in code_map.get("modules", {}).items():
        for cls_name, cls_data in mod.get("classes", {}).items():
            for method_sig in cls_data.get("methods", []):
                method_name = _method_name(method_sig)
                symbols.append((path, cls_data.get("rank", 0), "method", method_name, cls_name))
            symbols.append((path, cls_data.get("rank", 0), "class", cls_name, None))
        for func_name, func_data in mod.get("functions", {}).items():
            symbols.append((path, func_data.get("rank", 0), "function", func_name, None))
    return symbols


def _remove_symbol(
    code_map: dict, path: str, kind: str, name: str, parent: str | None,
) -> None:
    mod = code_map["modules"].get(path)
    if mod is None:
        return
    if kind == "method" and parent:
        cls_data = mod.get("classes", {}).get(parent)
        if cls_data:
            cls_data["methods"] = [
                m for m in cls_data["methods"] if _method_name(m) != name
            ]
    elif kind == "function":
        mod.get("functions", {}).pop(name, None)
    elif kind == "class":
        mod.get("classes", {}).pop(name, None)


def _method_name(sig: str) -> str:
    return sig.split("(", 1)[0].strip()


def _is_internal_import(imp: str, internal_modules: set[str]) -> bool:
    if imp in internal_modules:
        return True
    if "." in imp:
        parent = imp.rsplit(".", 1)[0]
        return parent in internal_modules
    return False


# -- Generator (orchestrator) ------------------------------------------------


def _get_git_commit(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def generate_code_map(
    repo_root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    max_tokens: int | None = None,
    project_id: str = "",
) -> dict:
    modules = parse_modules(repo_root, scope, exclude)
    graph = build_reference_graph(modules)
    ranks = rank_symbols(graph)
    commit = _get_git_commit(repo_root)

    code_map = assemble_code_map(
        modules, ranks, repo_root_name=project_id, commit=commit,
    )

    if max_tokens:
        code_map = trim_by_rank(code_map, max_tokens)

    return code_map


# -- CLI ---------------------------------------------------------------------


def _print_stats(code_map: dict) -> None:
    stats = code_map.get("stats", {})
    modules = code_map.get("modules", {})

    print(f"Project:    {code_map.get('project_id', 'unknown')}")
    print(f"Commit:     {code_map.get('commit', 'unknown')[:12]}")
    print(f"Files:      {stats.get('total_files', 0)}")
    print(f"Lines:      {stats.get('total_lines', 0):,}")
    print(f"Classes:    {stats.get('total_classes', 0)}")
    print(f"Functions:  {stats.get('total_functions', 0)}")
    print()

    ranked = sorted(
        modules.items(),
        key=lambda x: x[1].get("rank", 0),
        reverse=True,
    )[:10]

    print("Top 10 files by PageRank:")
    for path, mod in ranked:
        rank = mod.get("rank", 0)
        lines = mod.get("lines", 0)
        n_classes = len(mod.get("classes", {}))
        n_funcs = len(mod.get("functions", {}))
        print(f"  {rank:.4f}  {path} ({lines} lines, {n_classes}C {n_funcs}F)")

    graph = code_map.get("import_graph", {})
    total_edges = sum(len(v) for v in graph.values())
    print(f"\nImport graph: {len(graph)} modules, {total_edges} edges")

    json_tokens = len(json.dumps(code_map)) // 4
    md_tokens = len(render_markdown_tree(code_map)) // 4
    print(f"\nEstimated tokens: ~{json_tokens:,} (JSON), ~{md_tokens:,} (Markdown)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a structural code map of the repository.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="Maximum token budget for the output",
    )
    parser.add_argument(
        "--scope",
        nargs="*",
        default=["src/security_review/", "scripts/"],
        help="Directories or files to include (default: src/security_review/ scripts/)",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=["tests/", "__pycache__/"],
        help="Patterns to exclude (default: tests/ __pycache__/)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print summary statistics only",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Write output to file instead of default (.codemap/ folder)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print to stdout instead of writing to .codemap/",
    )

    args = parser.parse_args()

    exclude = args.exclude or [
        ".venv/",
        "__pycache__/",
        ".git/",
        "node_modules/",
        ".mypy_cache/",
        ".pytest_cache/",
        ".ruff_cache/",
    ]

    code_map = generate_code_map(
        repo_root=PROJECT_ROOT,
        scope=args.scope,
        exclude=exclude,
        project_id=PROJECT_ROOT.name,
    )

    if args.stats:
        _print_stats(code_map)
        return

    if args.format == "json":
        if args.max_tokens:
            code_map = trim_by_rank(code_map, args.max_tokens)
        indent = 2 if args.pretty else None
        output = json.dumps(code_map, indent=indent)
    else:
        if args.max_tokens:
            output = render_for_agent(code_map, args.max_tokens)
        else:
            output = render_markdown_tree(code_map)

    if args.stdout:
        print(output)
        return

    if args.output:
        out_path = Path(args.output)
    else:
        codemap_dir = PROJECT_ROOT / ".codemap"
        codemap_dir.mkdir(exist_ok=True)
        ext = "json" if args.format == "json" else "md"
        out_path = codemap_dir / f"map.{ext}"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output, encoding="utf-8")
    stats = code_map.get("stats", {})
    print(
        f"Code map written to {out_path} "
        f"({stats.get('total_files', 0)} files, "
        f"{stats.get('total_lines', 0)} lines, "
        f"~{len(output) // 4} tokens)",
    )


if __name__ == "__main__":
    main()
