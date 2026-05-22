"""Python source file parser using stdlib ast."""

from __future__ import annotations

import ast
from pathlib import Path

from code_analysis.models import (
    FileMetrics,
    FileResult,
    ModuleInfo,
    SymbolInfo,
    SymbolKind,
)
from code_analysis.parsers import register_parser


UNSAFE_CALLS: dict[str, str] = {
    "eval": "CWE-94: Code injection via eval()",
    "exec": "CWE-94: Code injection via exec()",
    "compile": "CWE-94: compile() with exec mode",
    "__import__": "CWE-94: Dynamic import",
}

UNSAFE_ATTRS: dict[tuple[str, str], str] = {
    ("os", "system"): "CWE-78: OS command injection via os.system()",
    ("os", "popen"): "CWE-78: OS command injection via os.popen()",
    ("pickle", "loads"): "CWE-502: Deserialization via pickle.loads()",
    ("pickle", "load"): "CWE-502: Deserialization via pickle.load()",
    ("marshal", "loads"): "CWE-502: Deserialization via marshal.loads()",
    ("yaml", "load"): "CWE-502: yaml.load() without SafeLoader",
    ("shelve", "open"): "CWE-502: shelve.open() uses pickle internally",
    ("jsonpickle", "decode"): "CWE-502: jsonpickle.decode() deserializes arbitrary objects",
}


@register_parser
class PythonParser:
    """Python AST-based parser. No external dependencies."""

    @property
    def language(self) -> str:
        return "python"

    @property
    def extensions(self) -> set[str]:
        return {".py"}

    def analyze_file(
        self, file_path: Path, rel_path: str, *, include_structure: bool = False,
    ) -> FileResult | None:
        """Parse a Python file once, extract metrics and optionally structure."""
        try:
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            return None

        metrics = self._extract_metrics(tree, source, rel_path)
        module = self._extract_structure(tree, source, rel_path) if include_structure else None
        return FileResult(metrics=metrics, module=module)

    # -- Metric extraction ---------------------------------------------------

    def _extract_metrics(self, tree: ast.Module, source: str, rel_path: str) -> FileMetrics:
        line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)
        metrics = FileMetrics(path=rel_path, language="python", lines=line_count)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                metrics.classes += 1
                self._analyze_callable(node, metrics, is_class=True)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                metrics.functions += 1
                self._analyze_callable(node, metrics, is_class=False)
            elif isinstance(node, ast.ExceptHandler):
                self._analyze_except_handler(node, metrics)

        metrics.max_nesting = self._compute_max_nesting(tree)
        metrics.unsafe_calls = self._detect_unsafe_patterns(tree)
        metrics.naming_violations = self._count_naming_violations(tree)
        return metrics

    def _analyze_callable(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        metrics: FileMetrics,
        is_class: bool,
    ) -> None:
        if isinstance(node, ast.ClassDef):
            metrics.total_callables += 1
            if ast.get_docstring(node):
                metrics.documented_callables += 1
            if node.name.startswith("_"):
                metrics.private_definitions += 1
            else:
                metrics.public_definitions += 1
            return

        metrics.total_callables += 1
        if ast.get_docstring(node):
            metrics.documented_callables += 1

        if node.end_lineno and node.lineno:
            metrics.function_lengths.append(node.end_lineno - node.lineno + 1)

        for arg in node.args.args:
            if is_class and arg.arg in ("self", "cls"):
                continue
            metrics.total_params += 1
            if arg.annotation is not None:
                metrics.annotated_params += 1

        metrics.total_returns += 1
        if node.returns is not None:
            metrics.annotated_returns += 1

        if node.name.startswith("_") and not node.name.startswith("__"):
            metrics.private_definitions += 1
        else:
            metrics.public_definitions += 1

    def _analyze_except_handler(self, node: ast.ExceptHandler, metrics: FileMetrics) -> None:
        metrics.exception_handlers += 1
        if node.type is None:
            metrics.bare_excepts += 1
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            metrics.broad_excepts += 1
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            metrics.bare_excepts += 1

    def _compute_max_nesting(self, tree: ast.Module) -> int:
        max_depth = 0

        def walk(node: ast.AST, depth: int) -> None:
            nonlocal max_depth
            if isinstance(node, (ast.If, ast.For, ast.While, ast.With,
                                 ast.Try, ast.AsyncFor, ast.AsyncWith)):
                depth += 1
                max_depth = max(max_depth, depth)
            for child in ast.iter_child_nodes(node):
                walk(child, depth)

        walk(tree, 0)
        return max_depth

    def _detect_unsafe_patterns(self, tree: ast.Module) -> list[str]:
        findings: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in UNSAFE_CALLS:
                findings.append(f"line {node.lineno}: {UNSAFE_CALLS[node.func.id]}")
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                key = (node.func.value.id, node.func.attr)
                if key in UNSAFE_ATTRS:
                    findings.append(f"line {node.lineno}: {UNSAFE_ATTRS[key]}")
                if node.func.value.id == "subprocess":
                    for kw in node.keywords:
                        if (kw.arg == "shell"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is True):
                            findings.append(
                                f"line {node.lineno}: CWE-78: subprocess with shell=True"
                            )
        return findings

    def _count_naming_violations(self, tree: ast.Module) -> int:
        violations = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.name[0].islower() and not node.name.startswith("_"):
                    violations += 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name
                if (not name.startswith("__")
                        and not name.islower()
                        and name != name.lower()
                        and any(c.isupper() for c in name[1:])
                        and "_" not in name):
                    violations += 1
        return violations

    # -- Structural extraction (only when include_structure=True) ------------

    def _extract_structure(self, tree: ast.Module, source: str, rel_path: str) -> ModuleInfo:
        line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)
        module_qname = _path_to_module(rel_path)

        return ModuleInfo(
            path=rel_path,
            language="python",
            lines=line_count,
            imports=self._extract_imports(tree),
            classes=self._extract_classes(tree, module_qname),
            functions=self._extract_functions(tree, module_qname),
            constants=self._extract_constants(tree),
            references=self._extract_references(tree),
        )

    def _extract_imports(self, tree: ast.Module) -> list[str]:
        imports: list[str] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        return imports

    def _extract_classes(self, tree: ast.Module, module_qname: str) -> list[SymbolInfo]:
        classes: list[SymbolInfo] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                classes.append(self._parse_class(node, module_qname))
        return classes

    def _parse_class(self, node: ast.ClassDef, module_qname: str) -> SymbolInfo:
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
                methods.append(self._parse_function(item, class_qname, is_method=True))

        return SymbolInfo(
            name=node.name, kind=SymbolKind.CLASS, qualified_name=class_qname,
            line=node.lineno, end_line=node.end_lineno or node.lineno,
            bases=bases, fields=fields, methods=methods, decorators=decorators,
        )

    def _extract_functions(self, tree: ast.Module, module_qname: str) -> list[SymbolInfo]:
        functions: list[SymbolInfo] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(self._parse_function(node, module_qname, is_method=False))
        return functions

    def _parse_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent_qname: str,
        is_method: bool,
    ) -> SymbolInfo:
        params: list[str] = []
        for arg in node.args.args:
            if is_method and arg.arg in ("self", "cls"):
                continue
            annotation = _annotation_str(arg.annotation) if arg.annotation else ""
            params.append(f"{arg.arg}: {annotation}" if annotation else arg.arg)

        return_type = _annotation_str(node.returns) if node.returns else ""
        decorators = [_name_from_node(d) for d in node.decorator_list if _name_from_node(d)]

        return SymbolInfo(
            name=node.name,
            kind=SymbolKind.METHOD if is_method else SymbolKind.FUNCTION,
            qualified_name=f"{parent_qname}.{node.name}",
            line=node.lineno, end_line=node.end_lineno or node.lineno,
            params=params, return_type=return_type, decorators=decorators,
        )

    def _extract_constants(self, tree: ast.Module) -> list[str]:
        constants: list[str] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name = node.target.id
                if name.isupper() or (name.startswith("_") and name[1:].isupper()):
                    constants.append(f"{name}: {_annotation_str(node.annotation)}")
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        constants.append(target.id)
        return constants

    def _extract_references(self, tree: ast.Module) -> list[str]:
        refs: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                refs.add(node.id)
            elif isinstance(node, ast.Attribute):
                chain = _attribute_chain(node)
                if chain:
                    refs.add(chain)
        return sorted(refs)


# -- AST helper functions (module-level) -------------------------------------


def _path_to_module(rel_path: str) -> str:
    module = rel_path.replace("/", ".").replace("\\", ".")
    if module.endswith(".py"):
        module = module[:-3]
    if module.endswith(".__init__"):
        module = module[:-9]
    if module.startswith("src."):
        module = module[4:]
    return module


def _name_from_node(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _attribute_chain(node)
    if isinstance(node, ast.Call):
        return _name_from_node(node.func)
    return ""


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
        return f"{_annotation_str(node.value)}[{_annotation_str(node.slice)}]"
    if isinstance(node, ast.Tuple):
        return ", ".join(_annotation_str(e) for e in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return f"{_annotation_str(node.left)} | {_annotation_str(node.right)}"
    return ast.dump(node)
