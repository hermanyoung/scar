"""C# source file parser using tree-sitter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from code_analysis.models import (
    FileMetrics,
    FileResult,
    ModuleInfo,
    SymbolInfo,
    SymbolKind,
)
from code_analysis.parsers import register_parser


UNSAFE_TYPE_NAMES: dict[str, str] = {
    "BinaryFormatter": "CWE-502: BinaryFormatter deserialization",
    "NetDataContractSerializer": "CWE-502: NetDataContractSerializer deserialization",
    "LosFormatter": "CWE-502: LosFormatter deserialization",
    "SoapFormatter": "CWE-502: SoapFormatter deserialization",
    "ObjectStateFormatter": "CWE-502: ObjectStateFormatter deserialization",
    "JavaScriptSerializer": "CWE-502: JavaScriptSerializer with type resolver",
}

UNSAFE_METHOD_CALLS: dict[str, str] = {
    "Process.Start": "CWE-78: OS command injection via Process.Start",
    "Assembly.Load": "CWE-94: Dynamic assembly loading",
    "Assembly.LoadFrom": "CWE-94: Dynamic assembly loading from path",
    "Assembly.LoadFile": "CWE-94: Dynamic assembly loading from file",
    "Type.InvokeMember": "CWE-94: Reflection-based member invocation",
    "Activator.CreateInstance": "CWE-94: Dynamic type instantiation via reflection",
}

NESTING_TYPES: set[str] = {
    "if_statement", "for_statement", "foreach_statement",
    "while_statement", "do_statement", "try_statement",
    "using_statement", "switch_statement",
}


def _check_tree_sitter() -> tuple[Any, Any]:
    """Import tree-sitter dependencies. Raises ValueError if not installed."""
    try:
        import tree_sitter_c_sharp as ts_csharp
        from tree_sitter import Language, Parser
    except ImportError:
        raise ValueError(
            "C# analysis requires tree-sitter and tree-sitter-c-sharp.\n"
            "Install with: pip install tree-sitter tree-sitter-c-sharp"
        )
    language = Language(ts_csharp.language())
    parser = Parser(language)
    return parser, language


@register_parser
class CSharpParser:
    """C# parser using tree-sitter-c-sharp."""

    def __init__(self) -> None:
        self._parser: Any = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self._parser, _ = _check_tree_sitter()
            self._initialized = True

    @property
    def language(self) -> str:
        return "csharp"

    @property
    def extensions(self) -> set[str]:
        return {".cs"}

    def analyze_file(
        self, file_path: Path, rel_path: str, *, include_structure: bool = False,
    ) -> FileResult | None:
        """Parse a C# file once, extract metrics and optionally structure."""
        self._ensure_initialized()

        try:
            source_bytes = file_path.read_bytes()
            source = source_bytes.decode("utf-8", errors="replace")
        except OSError:
            return None

        tree = self._parser.parse(source_bytes)
        root = tree.root_node

        metrics = self._extract_metrics(root, source, rel_path)
        module = self._extract_structure(root, source, rel_path) if include_structure else None
        return FileResult(metrics=metrics, module=module)

    # -- Metric extraction ---------------------------------------------------

    def _extract_metrics(self, root: Any, source: str, rel_path: str) -> FileMetrics:
        line_count = source.count("\n") + 1
        metrics = FileMetrics(path=rel_path, language="csharp", lines=line_count)

        for node in self._walk(root):
            if node.type == "class_declaration":
                metrics.classes += 1
                metrics.total_callables += 1
                self._analyze_class_metrics(node, source, metrics)

            elif node.type == "method_declaration":
                metrics.methods += 1
                metrics.functions += 1
                metrics.total_callables += 1
                self._analyze_method_metrics(node, source, metrics)

            elif node.type == "catch_clause":
                self._analyze_catch_metrics(node, source, metrics)

        metrics.max_nesting = self._compute_nesting(root)
        metrics.unsafe_calls = self._detect_unsafe_patterns(root, source)
        metrics.naming_violations = self._count_naming_violations(root, source)

        # C#-specific robustness signals
        metrics.nullable_enabled = "#nullable enable" in source
        metrics.null_forgiving_count = self._count_null_forgiving(root)
        metrics.sealed_classes = self._count_sealed_classes(root, source)

        return metrics

    def _analyze_class_metrics(self, node: Any, source: str, metrics: FileMetrics) -> None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return
        # Check XML doc comment
        if self._has_doc_comment(node, source):
            metrics.documented_callables += 1
        # Accessibility
        modifiers = self._get_modifiers(node, source)
        if "private" in modifiers or "internal" in modifiers:
            metrics.private_definitions += 1
        else:
            metrics.public_definitions += 1

    def _analyze_method_metrics(self, node: Any, source: str, metrics: FileMetrics) -> None:
        length = node.end_point[0] - node.start_point[0] + 1
        metrics.function_lengths.append(length)

        # Doc comment
        if self._has_doc_comment(node, source):
            metrics.documented_callables += 1

        # Return type
        metrics.total_returns += 1
        ret_type = node.child_by_field_name("type")
        if ret_type and self._node_text(ret_type, source) != "void":
            metrics.annotated_returns += 1

        # Parameters (C# params always have types)
        params = node.child_by_field_name("parameters")
        if params:
            for child in params.children:
                if child.type == "parameter":
                    metrics.total_params += 1
                    metrics.annotated_params += 1

        # Accessibility
        modifiers = self._get_modifiers(node, source)
        if "private" in modifiers or "internal" in modifiers:
            metrics.private_definitions += 1
        else:
            metrics.public_definitions += 1

    def _analyze_catch_metrics(self, node: Any, source: str, metrics: FileMetrics) -> None:
        metrics.exception_handlers += 1
        decl = node.child_by_field_name("declaration")
        if decl is None:
            metrics.bare_excepts += 1
        else:
            catch_type = self._node_text(decl, source)
            if "Exception" in catch_type and "Specific" not in catch_type:
                metrics.broad_excepts += 1
        # Empty catch body
        body = node.child_by_field_name("body")
        if body:
            meaningful = [c for c in body.children if c.type not in ("{", "}", "comment")]
            if not meaningful:
                metrics.bare_excepts += 1

    def _compute_nesting(self, root: Any) -> int:
        max_depth = 0

        def walk(node: Any, depth: int) -> None:
            nonlocal max_depth
            if node.type in NESTING_TYPES:
                depth += 1
                max_depth = max(max_depth, depth)
            for child in node.children:
                walk(child, depth)

        walk(root, 0)
        return max_depth

    def _detect_unsafe_patterns(self, root: Any, source: str) -> list[str]:
        findings: list[str] = []
        for node in self._walk(root):
            # Object creation: new BinaryFormatter(), etc.
            if node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node:
                    type_name = self._node_text(type_node, source).rsplit(".", 1)[-1]
                    if type_name in UNSAFE_TYPE_NAMES:
                        line = node.start_point[0] + 1
                        findings.append(f"line {line}: {UNSAFE_TYPE_NAMES[type_name]}")
                    # SqlCommand with string concatenation
                    if type_name in ("SqlCommand", "SqlDataAdapter"):
                        args = node.child_by_field_name("arguments")
                        if args and self._contains_concat(args, source):
                            line = node.start_point[0] + 1
                            findings.append(
                                f"line {line}: CWE-89: {type_name} with string concatenation"
                            )

            # Method invocations: Process.Start(), Assembly.Load(), etc.
            if node.type == "invocation_expression":
                func_node = node.child_by_field_name("function")
                if func_node:
                    func_text = self._node_text(func_node, source)
                    for pattern, desc in UNSAFE_METHOD_CALLS.items():
                        if func_text.endswith(pattern) or func_text == pattern:
                            line = node.start_point[0] + 1
                            findings.append(f"line {line}: {desc}")

            # TypeNameHandling assignment
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right:
                    left_text = self._node_text(left, source)
                    right_text = self._node_text(right, source)
                    if "TypeNameHandling" in left_text and right_text != "TypeNameHandling.None":
                        line = node.start_point[0] + 1
                        findings.append(
                            f"line {line}: CWE-502: Newtonsoft TypeNameHandling set to {right_text}"
                        )

        return findings

    def _count_naming_violations(self, root: Any, source: str) -> int:
        violations = 0
        for node in self._walk(root):
            if node.type == "method_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = self._node_text(name_node, source)
                    # C# methods should be PascalCase
                    if name and name[0].islower() and not name.startswith("_"):
                        violations += 1
            elif node.type in ("class_declaration", "struct_declaration", "record_declaration"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = self._node_text(name_node, source)
                    if name and name[0].islower() and not name.startswith("_"):
                        violations += 1
        return violations

    def _count_null_forgiving(self, root: Any) -> int:
        count = 0
        for node in self._walk(root):
            if node.type == "suppression_expression":
                count += 1
        return count

    def _count_sealed_classes(self, root: Any, source: str) -> int:
        count = 0
        for node in self._walk(root):
            if node.type == "class_declaration":
                modifiers = self._get_modifiers(node, source)
                if "sealed" in modifiers:
                    count += 1
        return count

    # -- Structural extraction (only when include_structure=True) ------------

    def _extract_structure(self, root: Any, source: str, rel_path: str) -> ModuleInfo:
        line_count = source.count("\n") + 1
        module_qname = _path_to_module(rel_path)

        imports = self._extract_using_directives(root, source)
        classes = self._extract_class_symbols(root, source, module_qname)

        return ModuleInfo(
            path=rel_path,
            language="csharp",
            lines=line_count,
            imports=imports,
            classes=classes,
            functions=[],  # C# top-level functions are rare
            constants=[],
        )

    def _extract_using_directives(self, root: Any, source: str) -> list[str]:
        imports: list[str] = []
        for node in root.children:
            if node.type == "using_directive":
                name_node = node.child_by_field_name("name")
                if name_node:
                    imports.append(self._node_text(name_node, source))
        return imports

    def _extract_class_symbols(self, root: Any, source: str, module_qname: str) -> list[SymbolInfo]:
        classes: list[SymbolInfo] = []

        for node in self._walk(root):
            if node.type not in ("class_declaration", "record_declaration", "struct_declaration"):
                continue
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            name = self._node_text(name_node, source)

            # Base types
            bases: list[str] = []
            base_list = node.child_by_field_name("bases")
            if base_list:
                for child in base_list.children:
                    if child.type in ("identifier", "generic_name", "qualified_name"):
                        bases.append(self._node_text(child, source))

            # Attributes (decorators)
            decorators: list[str] = []
            for child in node.children:
                if child.type == "attribute_list":
                    decorators.append(self._node_text(child, source).strip("[]"))

            # Methods
            methods: list[SymbolInfo] = []
            class_qname = f"{module_qname}.{name}"
            body = node.child_by_field_name("body")
            if body:
                for member in body.children:
                    if member.type == "method_declaration":
                        method_name_node = member.child_by_field_name("name")
                        if method_name_node:
                            method_name = self._node_text(method_name_node, source)
                            params: list[str] = []
                            param_list = member.child_by_field_name("parameters")
                            if param_list:
                                for p in param_list.children:
                                    if p.type == "parameter":
                                        params.append(self._node_text(p, source))
                            ret_node = member.child_by_field_name("type")
                            ret_type = self._node_text(ret_node, source) if ret_node else ""
                            methods.append(SymbolInfo(
                                name=method_name, kind=SymbolKind.METHOD,
                                qualified_name=f"{class_qname}.{method_name}",
                                line=member.start_point[0] + 1,
                                end_line=member.end_point[0] + 1,
                                params=params, return_type=ret_type,
                            ))

            # Fields
            fields: list[str] = []
            if body:
                for member in body.children:
                    if member.type in ("field_declaration", "property_declaration"):
                        fields.append(
                            self._node_text(member, source).split("\n")[0].strip().rstrip(";")
                        )

            classes.append(SymbolInfo(
                name=name, kind=SymbolKind.CLASS, qualified_name=class_qname,
                line=node.start_point[0] + 1, end_line=node.end_point[0] + 1,
                bases=bases, fields=fields, methods=methods, decorators=decorators,
            ))
        return classes

    # -- tree-sitter helpers -------------------------------------------------

    def _walk(self, node: Any) -> list[Any]:
        """Collect all nodes in tree-sitter AST (pre-order)."""
        result = [node]
        for child in node.children:
            result.extend(self._walk(child))
        return result

    def _node_text(self, node: Any, source: str) -> str:
        return source[node.start_byte:node.end_byte]

    def _get_modifiers(self, node: Any, source: str) -> set[str]:
        modifiers: set[str] = set()
        for child in node.children:
            if child.type == "modifier":
                modifiers.add(self._node_text(child, source))
        return modifiers

    def _has_doc_comment(self, node: Any, source: str) -> bool:
        """Check for XML documentation comment preceding a declaration."""
        if node.start_point[0] == 0:
            return False
        # Look at lines above the node for ///
        start_line = node.start_point[0]
        lines = source.split("\n")
        for i in range(start_line - 1, max(start_line - 5, -1), -1):
            stripped = lines[i].strip() if i < len(lines) else ""
            if stripped.startswith("///"):
                return True
            if stripped and not stripped.startswith("//") and not stripped.startswith("["):
                break
        return False

    def _contains_concat(self, node: Any, source: str) -> bool:
        """Check if a node contains string concatenation."""
        for child in self._walk(node):
            if child.type == "binary_expression":
                op = child.child_by_field_name("operator")
                if op and self._node_text(op, source) == "+":
                    return True
            if child.type == "interpolated_string_expression":
                return True
        return False


def _path_to_module(rel_path: str) -> str:
    module = rel_path.replace("/", ".").replace("\\", ".")
    if module.endswith(".cs"):
        module = module[:-3]
    return module
