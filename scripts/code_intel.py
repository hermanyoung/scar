#!/usr/bin/env python3
"""Code Intelligence — structural analysis for security review prioritisation.

Language-agnostic structural analysis with pluggable parsers for Python and C#.
Produces a unified code map with PageRank importance, unsafe pattern detection,
quality metrics, and composite security-weight scoring.

Feeds three pipeline stages:
  Pass 1 (Inventory): PageRank + unsafe patterns → security-weight scoring
  Pass 3 (Triage):    Quality baseline → confidence calibration
  Pass 4 (Holistic):  Structural map → token-budgeted LLM context

Usage:
    python scripts/code_intel.py --target .                        # Full analysis, Markdown
    python scripts/code_intel.py --target ../other-repo --json     # JSON output
    python scripts/code_intel.py --target . --max-tokens 8192      # Token-budgeted for LLM
    python scripts/code_intel.py --target . --stats                # Summary statistics
    python scripts/code_intel.py --target . --weights              # Security-weight ranking
    python scripts/code_intel.py --target . --unsafe               # Unsafe pattern report
    python scripts/code_intel.py --target . --quality              # Quality metrics report
"""

from __future__ import annotations

import argparse
import ast
import copy
import datetime
import json
import subprocess
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ============================================================================
# Types
# ============================================================================


class SymbolKind(str, Enum):
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    CONSTANT = "constant"
    PROPERTY = "property"


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
class UnsafePattern:
    file_path: str
    line: int
    pattern_name: str
    cwe_id: str
    description: str
    severity: str = "HIGH"  # HIGH, MEDIUM, LOW


@dataclass
class FileMetrics:
    path: str
    lines: int = 0
    functions: int = 0
    classes: int = 0
    methods: int = 0
    documented_callables: int = 0
    total_callables: int = 0
    annotated_params: int = 0
    total_params: int = 0
    annotated_returns: int = 0
    total_returns: int = 0
    exception_handlers: int = 0
    bare_excepts: int = 0
    broad_excepts: int = 0
    max_nesting: int = 0
    function_lengths: list[int] = field(default_factory=list)
    public_definitions: int = 0
    private_definitions: int = 0

    @property
    def type_coverage(self) -> float:
        total = self.total_params + self.total_returns
        annotated = self.annotated_params + self.annotated_returns
        return annotated / total if total > 0 else 1.0

    @property
    def avg_function_length(self) -> float:
        return sum(self.function_lengths) / len(self.function_lengths) if self.function_lengths else 0.0

    @property
    def bare_except_count(self) -> int:
        return self.bare_excepts


@dataclass
class ModuleInfo:
    path: str
    language: str
    lines: int
    imports: list[str]
    classes: list[SymbolInfo]
    functions: list[SymbolInfo]
    constants: list[str]
    references: list[str] = field(default_factory=list)


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


@dataclass
class SecurityWeight:
    file_path: str
    total: float
    pagerank_score: float
    unsafe_score: float
    surface_score: float
    quality_penalty: float
    unsafe_patterns: list[UnsafePattern]


@dataclass
class CodeIntelResult:
    target_path: str
    commit: str
    generated_at: str
    modules: list[ModuleInfo]
    graph: ReferenceGraph
    ranks: dict[str, float]
    metrics: dict[str, FileMetrics]
    unsafe: dict[str, list[UnsafePattern]]
    weights: dict[str, SecurityWeight]
    quality_summary: dict[str, Any]


# ============================================================================
# Language Parser ABC
# ============================================================================


class LanguageParser(ABC):
    """Abstract parser for extracting structural information from source files."""

    @abstractmethod
    def parse_file(self, file_path: Path, rel_path: str) -> ModuleInfo | None:
        """Extract module structure. Returns None on parse failure."""

    @abstractmethod
    def detect_unsafe_patterns(self, file_path: Path, rel_path: str) -> list[UnsafePattern]:
        """Detect security-relevant patterns via AST inspection."""

    @abstractmethod
    def compute_file_metrics(self, file_path: Path, rel_path: str) -> FileMetrics | None:
        """Compute quality metrics for a single file."""

    @property
    @abstractmethod
    def language(self) -> str:
        """Language identifier: 'python' or 'csharp'."""

    @property
    @abstractmethod
    def extensions(self) -> list[str]:
        """File extensions this parser handles."""


# ============================================================================
# Python Parser
# ============================================================================


class PythonParser(LanguageParser):

    UNSAFE_CALLS: dict[str, tuple[str, str]] = {
        "eval": ("CWE-94", "Code injection via eval()"),
        "exec": ("CWE-94", "Code injection via exec()"),
        "compile": ("CWE-94", "compile() with exec mode can execute arbitrary code"),
        "__import__": ("CWE-94", "Dynamic import can load arbitrary modules"),
    }

    UNSAFE_ATTRS: dict[tuple[str, str], tuple[str, str]] = {
        ("os", "system"): ("CWE-78", "OS command injection via os.system()"),
        ("os", "popen"): ("CWE-78", "OS command injection via os.popen()"),
        ("pickle", "loads"): ("CWE-502", "Deserialization of untrusted data via pickle.loads()"),
        ("pickle", "load"): ("CWE-502", "Deserialization of untrusted data via pickle.load()"),
        ("marshal", "loads"): ("CWE-502", "Deserialization via marshal.loads()"),
        ("yaml", "load"): ("CWE-502", "yaml.load() without SafeLoader"),
        ("shelve", "open"): ("CWE-502", "shelve.open() uses pickle internally"),
        ("jsonpickle", "decode"): ("CWE-502", "jsonpickle.decode() deserializes arbitrary objects"),
    }

    SURFACE_DECORATORS = {
        "app.route", "app.get", "app.post", "app.put", "app.delete", "app.patch",
        "router.get", "router.post", "router.put", "router.delete", "router.patch",
        "login_required", "require_http_methods",
    }

    @property
    def language(self) -> str:
        return "python"

    @property
    def extensions(self) -> list[str]:
        return [".py"]

    def parse_file(self, file_path: Path, rel_path: str) -> ModuleInfo | None:
        try:
            source = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            return None

        line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)
        imports = self._extract_imports(tree)
        classes = self._extract_classes(tree, rel_path)
        functions = self._extract_functions(tree, rel_path)
        constants = self._extract_constants(tree)
        references = self._extract_references(tree)

        return ModuleInfo(
            path=rel_path,
            language="python",
            lines=line_count,
            imports=imports,
            classes=classes,
            functions=functions,
            constants=constants,
            references=references,
        )

    def detect_unsafe_patterns(self, file_path: Path, rel_path: str) -> list[UnsafePattern]:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            return []

        findings: list[UnsafePattern] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Direct calls: eval(), exec(), etc.
                if isinstance(node.func, ast.Name) and node.func.id in self.UNSAFE_CALLS:
                    cwe, desc = self.UNSAFE_CALLS[node.func.id]
                    findings.append(UnsafePattern(
                        file_path=rel_path, line=node.lineno,
                        pattern_name=node.func.id, cwe_id=cwe, description=desc,
                    ))
                # Attribute calls: os.system(), pickle.loads(), etc.
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    key = (node.func.value.id, node.func.attr)
                    if key in self.UNSAFE_ATTRS:
                        cwe, desc = self.UNSAFE_ATTRS[key]
                        findings.append(UnsafePattern(
                            file_path=rel_path, line=node.lineno,
                            pattern_name=f"{key[0]}.{key[1]}", cwe_id=cwe, description=desc,
                        ))
                # subprocess with shell=True
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "subprocess":
                        for kw in node.keywords:
                            if (kw.arg == "shell"
                                    and isinstance(kw.value, ast.Constant)
                                    and kw.value.value is True):
                                findings.append(UnsafePattern(
                                    file_path=rel_path, line=node.lineno,
                                    pattern_name="subprocess.shell=True",
                                    cwe_id="CWE-78",
                                    description="subprocess with shell=True enables command injection",
                                ))
        return findings

    def compute_file_metrics(self, file_path: Path, rel_path: str) -> FileMetrics | None:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            return None

        line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)
        metrics = FileMetrics(path=rel_path, lines=line_count)

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
        return metrics

    # -- Structural extraction -----------------------------------------------

    def _extract_imports(self, tree: ast.Module) -> list[str]:
        imports: list[str] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        return imports

    def _extract_classes(self, tree: ast.Module, module_path: str) -> list[SymbolInfo]:
        classes: list[SymbolInfo] = []
        module_qname = _path_to_module(module_path)
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

    def _extract_functions(self, tree: ast.Module, module_path: str) -> list[SymbolInfo]:
        functions: list[SymbolInfo] = []
        module_qname = _path_to_module(module_path)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(self._parse_function(node, module_qname, is_method=False))
        return functions

    def _parse_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent_qname: str, is_method: bool,
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

    # -- Quality metrics -----------------------------------------------------

    def _analyze_callable(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        metrics: FileMetrics, is_class: bool,
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


# ============================================================================
# C# Parser
# ============================================================================


class CSharpParser(LanguageParser):
    """C# structural parser using tree-sitter-c-sharp.

    Falls back gracefully if tree-sitter is not installed — returns empty
    results with a warning, allowing the pipeline to proceed with Python-only
    analysis.
    """

    UNSAFE_TYPE_NAMES: dict[str, tuple[str, str, str]] = {
        # type_name: (cwe_id, description, severity)
        "BinaryFormatter": ("CWE-502", "BinaryFormatter deserialization", "CRITICAL"),
        "NetDataContractSerializer": ("CWE-502", "NetDataContractSerializer deserialization", "CRITICAL"),
        "LosFormatter": ("CWE-502", "LosFormatter deserialization", "CRITICAL"),
        "SoapFormatter": ("CWE-502", "SoapFormatter deserialization", "CRITICAL"),
        "ObjectStateFormatter": ("CWE-502", "ObjectStateFormatter deserialization", "CRITICAL"),
        "JavaScriptSerializer": ("CWE-502", "JavaScriptSerializer with type resolver", "HIGH"),
    }

    UNSAFE_METHOD_CALLS: dict[str, tuple[str, str]] = {
        "Process.Start": ("CWE-78", "OS command injection via Process.Start"),
        "Assembly.Load": ("CWE-94", "Dynamic assembly loading"),
        "Assembly.LoadFrom": ("CWE-94", "Dynamic assembly loading from path"),
        "Assembly.LoadFile": ("CWE-94", "Dynamic assembly loading from file"),
        "Type.InvokeMember": ("CWE-94", "Reflection-based member invocation"),
        "Activator.CreateInstance": ("CWE-94", "Dynamic type instantiation via reflection"),
    }

    SECURITY_ATTRIBUTES = {
        "Authorize", "AllowAnonymous", "HttpGet", "HttpPost", "HttpPut",
        "HttpDelete", "HttpPatch", "Route", "ApiController",
        "ValidateAntiForgeryToken",
    }

    SURFACE_ATTRIBUTES = {
        "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch",
        "ApiController", "Route", "Controller",
    }

    def __init__(self) -> None:
        try:
            import tree_sitter_c_sharp as ts_csharp
            from tree_sitter import Language, Parser
        except ImportError:
            raise RuntimeError(
                "C# parsing requires tree-sitter and tree-sitter-c-sharp.\n"
                "Install with: pip install tree-sitter tree-sitter-c-sharp"
            )
        self._ts_language = Language(ts_csharp.language())
        self._parser = Parser(self._ts_language)

    @property
    def language(self) -> str:
        return "csharp"

    @property
    def extensions(self) -> list[str]:
        return [".cs"]

    def parse_file(self, file_path: Path, rel_path: str) -> ModuleInfo | None:
        try:
            source = file_path.read_bytes()
            source_text = source.decode("utf-8", errors="replace")
        except OSError:
            return None

        tree = self._parser.parse(source)
        root = tree.root_node

        line_count = source_text.count("\n") + 1
        imports = self._extract_using_directives(root, source_text)
        classes = self._extract_classes(root, source_text, rel_path)
        functions: list[SymbolInfo] = []  # C# top-level functions are rare
        constants: list[str] = []

        return ModuleInfo(
            path=rel_path, language="csharp", lines=line_count,
            imports=imports, classes=classes, functions=functions,
            constants=constants,
        )

    def detect_unsafe_patterns(self, file_path: Path, rel_path: str) -> list[UnsafePattern]:
        try:
            source = file_path.read_bytes()
            source_text = source.decode("utf-8", errors="replace")
        except OSError:
            return []

        tree = self._parser.parse(source)
        findings: list[UnsafePattern] = []

        for node in self._walk(tree.root_node):
            node_text = self._node_text(node, source_text)

            # Object creation: new BinaryFormatter(), new SoapFormatter(), etc.
            if node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node:
                    type_name = self._node_text(type_node, source_text)
                    simple_name = type_name.rsplit(".", 1)[-1]
                    if simple_name in self.UNSAFE_TYPE_NAMES:
                        cwe, desc, sev = self.UNSAFE_TYPE_NAMES[simple_name]
                        findings.append(UnsafePattern(
                            file_path=rel_path, line=node.start_point[0] + 1,
                            pattern_name=simple_name, cwe_id=cwe,
                            description=desc, severity=sev,
                        ))

            # Method invocations: Process.Start(), Assembly.Load(), etc.
            if node.type == "invocation_expression":
                func_node = node.child_by_field_name("function")
                if func_node:
                    func_text = self._node_text(func_node, source_text)
                    for pattern, (cwe, desc) in self.UNSAFE_METHOD_CALLS.items():
                        if func_text.endswith(pattern) or func_text == pattern:
                            findings.append(UnsafePattern(
                                file_path=rel_path, line=node.start_point[0] + 1,
                                pattern_name=pattern, cwe_id=cwe, description=desc,
                            ))

            # SqlCommand/SqlDataAdapter with string concatenation
            if node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node:
                    type_name = self._node_text(type_node, source_text).rsplit(".", 1)[-1]
                    if type_name in ("SqlCommand", "SqlDataAdapter"):
                        args = node.child_by_field_name("arguments")
                        if args and self._contains_concat(args, source_text):
                            findings.append(UnsafePattern(
                                file_path=rel_path, line=node.start_point[0] + 1,
                                pattern_name="sql_string_concat", cwe_id="CWE-89",
                                description=f"{type_name} with string concatenation",
                            ))

            # TypeNameHandling assignment (Newtonsoft.Json)
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right:
                    left_text = self._node_text(left, source_text)
                    right_text = self._node_text(right, source_text)
                    if "TypeNameHandling" in left_text and right_text != "TypeNameHandling.None":
                        findings.append(UnsafePattern(
                            file_path=rel_path, line=node.start_point[0] + 1,
                            pattern_name="TypeNameHandling",
                            cwe_id="CWE-502",
                            description=f"Newtonsoft TypeNameHandling set to {right_text}",
                        ))

        return findings

    def compute_file_metrics(self, file_path: Path, rel_path: str) -> FileMetrics | None:
        try:
            source = file_path.read_bytes()
            source_text = source.decode("utf-8", errors="replace")
        except OSError:
            return None

        tree = self._parser.parse(source)
        line_count = source_text.count("\n") + 1
        metrics = FileMetrics(path=rel_path, lines=line_count)

        for node in self._walk(tree.root_node):
            if node.type == "class_declaration":
                metrics.classes += 1
                metrics.total_callables += 1
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = self._node_text(name_node, source_text)
                    if name.startswith("_"):
                        metrics.private_definitions += 1
                    else:
                        metrics.public_definitions += 1

            elif node.type == "method_declaration":
                metrics.methods += 1
                metrics.total_callables += 1
                length = node.end_point[0] - node.start_point[0] + 1
                metrics.function_lengths.append(length)

                # Check for return type
                metrics.total_returns += 1
                ret_type = node.child_by_field_name("type")
                if ret_type and self._node_text(ret_type, source_text) != "void":
                    metrics.annotated_returns += 1

                # Check parameters
                params = node.child_by_field_name("parameters")
                if params:
                    for child in params.children:
                        if child.type == "parameter":
                            metrics.total_params += 1
                            metrics.annotated_params += 1  # C# params always have types

                # Check accessibility
                modifiers = self._get_modifiers(node, source_text)
                if "private" in modifiers or "internal" in modifiers:
                    metrics.private_definitions += 1
                else:
                    metrics.public_definitions += 1

            elif node.type == "catch_clause":
                metrics.exception_handlers += 1
                decl = node.child_by_field_name("declaration") if hasattr(node, 'child_by_field_name') else None
                if decl is None:
                    metrics.bare_excepts += 1
                else:
                    catch_type = self._node_text(decl, source_text)
                    if "Exception" in catch_type and "Specific" not in catch_type:
                        metrics.broad_excepts += 1
                body = node.child_by_field_name("body")
                if body and len([c for c in body.children if c.type not in ("{", "}", "comment")]) == 0:
                    metrics.bare_excepts += 1

        metrics.max_nesting = self._compute_nesting(tree.root_node)
        return metrics

    # -- tree-sitter helpers -------------------------------------------------

    def _walk(self, node: Any) -> list[Any]:
        """Walk all nodes in tree-sitter AST."""
        result = [node]
        for child in node.children:
            result.extend(self._walk(child))
        return result

    def _node_text(self, node: Any, source: str) -> str:
        return source[node.start_byte:node.end_byte]

    def _contains_concat(self, node: Any, source: str) -> bool:
        """Check if a node contains string concatenation (binary + with string)."""
        for child in self._walk(node):
            if child.type == "binary_expression":
                op = child.child_by_field_name("operator")
                if op and self._node_text(op, source) == "+":
                    return True
            if child.type == "interpolated_string_expression":
                return True
        return False

    def _get_modifiers(self, node: Any, source: str) -> set[str]:
        modifiers: set[str] = set()
        for child in node.children:
            if child.type == "modifier":
                modifiers.add(self._node_text(child, source))
        return modifiers

    def _compute_nesting(self, root: Any) -> int:
        max_depth = 0
        nesting_types = {
            "if_statement", "for_statement", "foreach_statement",
            "while_statement", "do_statement", "try_statement",
            "using_statement", "switch_statement",
        }

        def walk(node: Any, depth: int) -> None:
            nonlocal max_depth
            if node.type in nesting_types:
                depth += 1
                max_depth = max(max_depth, depth)
            for child in node.children:
                walk(child, depth)

        walk(root, 0)
        return max_depth

    def _extract_using_directives(self, root: Any, source: str) -> list[str]:
        imports: list[str] = []
        for node in root.children:
            if node.type == "using_directive":
                name_node = node.child_by_field_name("name")
                if name_node:
                    imports.append(self._node_text(name_node, source))
        return imports

    def _extract_classes(self, root: Any, source: str, rel_path: str) -> list[SymbolInfo]:
        classes: list[SymbolInfo] = []
        module_qname = _path_to_module(rel_path)

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

            # Decorators (attributes)
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
                        fields.append(self._node_text(member, source).split("\n")[0].strip().rstrip(";"))

            classes.append(SymbolInfo(
                name=name, kind=SymbolKind.CLASS, qualified_name=class_qname,
                line=node.start_point[0] + 1, end_line=node.end_point[0] + 1,
                bases=bases, fields=fields, methods=methods, decorators=decorators,
            ))
        return classes



# ============================================================================
# AST Helper Functions (shared, language-agnostic where possible)
# ============================================================================


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


# ============================================================================
# Cross-Reference Graph + PageRank
# ============================================================================


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

        for func in module.functions:
            _add_symbol_references(func, module_qname, import_tables, known_symbols, edges)

    return ReferenceGraph(nodes=nodes, edges=list(set(edges)))


def compute_pagerank(
    graph: ReferenceGraph, damping: float = 0.85,
    max_iterations: int = 100, tolerance: float = 1e-6,
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


def _build_import_tables(modules: list[ModuleInfo], known_modules: set[str]) -> dict[str, dict[str, str]]:
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
    name: str, module_qname: str,
    import_tables: dict[str, dict[str, str]], known_symbols: dict[str, str],
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
    symbol: SymbolInfo, module_qname: str,
    import_tables: dict[str, dict[str, str]], known_symbols: dict[str, str],
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


# ============================================================================
# Security-Weight Composite Scorer
# ============================================================================


PYTHON_SURFACE_PATTERNS = {
    "app.route", "app.get", "app.post", "app.put", "app.delete",
    "router.get", "router.post", "router.put", "router.delete",
}

CSHARP_SURFACE_ATTRIBUTES = {
    "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch",
    "ApiController", "Route",
}


def compute_security_weight(
    module: ModuleInfo,
    pagerank: float,
    unsafe_patterns: list[UnsafePattern],
    metrics: FileMetrics | None,
) -> SecurityWeight:
    """Composite security-weight for a file. Higher = review first. Range 0-10."""

    # PageRank importance (0-3): blast radius of a vulnerability in this file
    pagerank_score = min(3.0, pagerank * 3.0)

    # Unsafe pattern count (0-3): direct indicator of likely true positives
    critical_count = sum(1 for p in unsafe_patterns if p.severity == "CRITICAL")
    high_count = sum(1 for p in unsafe_patterns if p.severity == "HIGH")
    unsafe_score = min(3.0, critical_count * 1.5 + high_count * 0.75)

    # External attack surface (0-2): is this an endpoint/controller?
    surface_score = 0.0
    if module.language == "python":
        all_decorators = set()
        for func in module.functions:
            all_decorators.update(func.decorators)
        for cls in module.classes:
            all_decorators.update(cls.decorators)
            for method in cls.methods:
                all_decorators.update(method.decorators)
        if any(d for d in all_decorators if any(p in d for p in PYTHON_SURFACE_PATTERNS)):
            surface_score = 2.0
    elif module.language == "csharp":
        all_attrs = set()
        for cls in module.classes:
            all_attrs.update(cls.decorators)
            if any(base in ("Controller", "ControllerBase", "ApiController")
                   for base in cls.bases):
                surface_score = 2.0
        if any(a for a in all_attrs if any(p in a for p in CSHARP_SURFACE_ATTRIBUTES)):
            surface_score = 2.0

    # Quality penalty (0-2): low quality = higher risk of latent bugs
    quality_penalty = 0.0
    if metrics:
        if metrics.type_coverage < 0.3:
            quality_penalty += 0.5
        if metrics.max_nesting > 5:
            quality_penalty += 0.5
        if metrics.bare_except_count > 0:
            quality_penalty += 0.5
        if metrics.avg_function_length > 60:
            quality_penalty += 0.5

    total = min(10.0, pagerank_score + unsafe_score + surface_score + quality_penalty)

    return SecurityWeight(
        file_path=module.path, total=total,
        pagerank_score=round(pagerank_score, 3),
        unsafe_score=round(unsafe_score, 3),
        surface_score=round(surface_score, 3),
        quality_penalty=round(quality_penalty, 3),
        unsafe_patterns=unsafe_patterns,
    )


# ============================================================================
# Quality Summary
# ============================================================================


def aggregate_quality_metrics(metrics: dict[str, FileMetrics]) -> dict[str, Any]:
    """Aggregate per-file metrics into a codebase quality summary."""
    if not metrics:
        return {"file_count": 0}

    all_metrics = list(metrics.values())
    total_lines = sum(m.lines for m in all_metrics)
    total_callables = sum(m.total_callables for m in all_metrics)
    documented = sum(m.documented_callables for m in all_metrics)
    total_params = sum(m.total_params for m in all_metrics)
    annotated_params = sum(m.annotated_params for m in all_metrics)
    total_returns = sum(m.total_returns for m in all_metrics)
    annotated_returns = sum(m.annotated_returns for m in all_metrics)
    total_handlers = sum(m.exception_handlers for m in all_metrics)
    bare = sum(m.bare_excepts for m in all_metrics)
    broad = sum(m.broad_excepts for m in all_metrics)

    all_lengths = [l for m in all_metrics for l in m.function_lengths]
    all_nesting = [m.max_nesting for m in all_metrics if m.max_nesting > 0]

    return {
        "file_count": len(all_metrics),
        "total_lines": total_lines,
        "doc_coverage": documented / total_callables if total_callables > 0 else 1.0,
        "param_type_coverage": annotated_params / total_params if total_params > 0 else 1.0,
        "return_type_coverage": annotated_returns / total_returns if total_returns > 0 else 1.0,
        "exception_handler_quality": (
            1.0 - (bare + broad) / total_handlers if total_handlers > 0 else 1.0
        ),
        "avg_function_length": sum(all_lengths) / len(all_lengths) if all_lengths else 0,
        "p90_function_length": (
            sorted(all_lengths)[min(int(len(all_lengths) * 0.9), len(all_lengths) - 1)]
            if all_lengths else 0
        ),
        "avg_max_nesting": sum(all_nesting) / len(all_nesting) if all_nesting else 0,
        "p90_nesting": (
            sorted(all_nesting)[min(int(len(all_nesting) * 0.9), len(all_nesting) - 1)]
            if all_nesting else 0
        ),
    }


# ============================================================================
# Renderer (token-budgeted Markdown)
# ============================================================================


def render_markdown(result: CodeIntelResult, max_tokens: int | None = None) -> str:
    lines: list[str] = []
    lines.append(f"# Code Intelligence — {Path(result.target_path).name}")
    lines.append("")

    total_files = len(result.modules)
    total_lines = sum(m.lines for m in result.modules)
    total_classes = sum(len(m.classes) for m in result.modules)
    total_functions = sum(len(m.functions) for m in result.modules)
    languages = sorted(set(m.language for m in result.modules))
    commit_short = result.commit[:12] if result.commit else "unknown"

    lines.append(
        f"**{total_files} files** | **{total_lines:,} lines** | "
        f"**{total_classes} classes** | **{total_functions} functions** | "
        f"languages: {', '.join(languages)} | commit `{commit_short}`"
    )
    lines.append("")

    # Security-weight ranking
    sorted_weights = sorted(result.weights.values(), key=lambda w: w.total, reverse=True)
    lines.append("## Security Priority (top 20)")
    lines.append("")
    lines.append("| Weight | File | PageRank | Unsafe | Surface | Quality |")
    lines.append("|--------|------|----------|--------|---------|---------|")
    for w in sorted_weights[:20]:
        lines.append(
            f"| **{w.total:.1f}** | {w.file_path} | {w.pagerank_score:.2f} | "
            f"{w.unsafe_score:.2f} | {w.surface_score:.2f} | {w.quality_penalty:.2f} |"
        )
    lines.append("")

    # Unsafe patterns
    all_unsafe = [p for patterns in result.unsafe.values() for p in patterns]
    if all_unsafe:
        lines.append("## Unsafe Patterns")
        lines.append("")
        for p in sorted(all_unsafe, key=lambda x: (x.severity != "CRITICAL", x.severity != "HIGH", x.file_path)):
            lines.append(f"- **{p.severity}** {p.file_path}:{p.line} — {p.pattern_name} ({p.cwe_id}): {p.description}")
        lines.append("")

    # Quality summary
    qs = result.quality_summary
    if qs.get("file_count", 0) > 0:
        lines.append("## Quality Baseline")
        lines.append("")
        lines.append(f"- Doc coverage: {qs.get('doc_coverage', 0):.0%}")
        lines.append(f"- Param type coverage: {qs.get('param_type_coverage', 0):.0%}")
        lines.append(f"- Return type coverage: {qs.get('return_type_coverage', 0):.0%}")
        lines.append(f"- Exception handling quality: {qs.get('exception_handler_quality', 0):.0%}")
        lines.append(f"- Avg function length: {qs.get('avg_function_length', 0):.0f} lines")
        lines.append(f"- P90 function length: {qs.get('p90_function_length', 0)} lines")
        lines.append(f"- P90 nesting depth: {qs.get('p90_nesting', 0)}")
        lines.append("")

    # Structural map (sorted by PageRank)
    lines.append("## Structure")
    lines.append("")

    module_ranks = {m.path: result.ranks.get(_path_to_module(m.path), 0) for m in result.modules}
    sorted_modules = sorted(result.modules, key=lambda m: module_ranks.get(m.path, 0), reverse=True)

    for module in sorted_modules:
        rank = module_ranks.get(module.path, 0)
        lines.append(f"{module.path} ({module.lines} lines, rank {rank:.3f}):")

        for cls in sorted(module.classes, key=lambda c: result.ranks.get(c.qualified_name, 0), reverse=True):
            bases_str = f"({', '.join(cls.bases)})" if cls.bases else ""
            attrs_str = f" [{', '.join(cls.decorators)}]" if cls.decorators else ""
            lines.append(f"│class {cls.name}{bases_str}{attrs_str}:")
            for fld in cls.fields[:5]:
                lines.append(f"│    {fld}")
            if len(cls.fields) > 5:
                lines.append(f"│    ... +{len(cls.fields) - 5} more fields")
            for method in cls.methods:
                params_str = ", ".join(method.params[:3])
                if len(method.params) > 3:
                    params_str += ", ..."
                ret = f" -> {method.return_type}" if method.return_type else ""
                lines.append(f"│    def {method.name}({params_str}){ret}")

        for func in sorted(module.functions, key=lambda f: result.ranks.get(f.qualified_name, 0), reverse=True):
            params_str = ", ".join(func.params[:3])
            if len(func.params) > 3:
                params_str += ", ..."
            ret = f" -> {func.return_type}" if func.return_type else ""
            decs = "".join(f"│@{d}\n" for d in func.decorators)
            if decs:
                lines.append(decs.rstrip("\n"))
            lines.append(f"│def {func.name}({params_str}){ret}")
        lines.append("")

    output = "\n".join(lines)

    # Token budget trimming
    if max_tokens and _estimate_tokens(output) > max_tokens:
        output = _trim_to_budget(lines, sorted_modules, result, max_tokens)

    return output


def _estimate_tokens(text: str) -> int:
    return len(text) // 4


def _trim_to_budget(
    lines: list[str], sorted_modules: list[ModuleInfo],
    result: CodeIntelResult, max_tokens: int,
) -> str:
    """Progressively trim low-PageRank content to fit token budget."""
    # Strategy: remove modules from the bottom of the rank list
    output = "\n".join(lines)
    modules_to_show = list(sorted_modules)

    while _estimate_tokens(output) > max_tokens and len(modules_to_show) > 1:
        modules_to_show.pop()
        trimmed_lines = lines[:lines.index("## Structure") + 2] if "## Structure" in lines else lines[:10]
        for module in modules_to_show:
            rank = result.ranks.get(_path_to_module(module.path), 0)
            trimmed_lines.append(f"{module.path} ({module.lines} lines, rank {rank:.3f})")
        trimmed_lines.append(f"\n... {len(sorted_modules) - len(modules_to_show)} low-priority files omitted")
        output = "\n".join(trimmed_lines)

    return output


def render_json(result: CodeIntelResult) -> dict:
    return {
        "target_path": result.target_path,
        "commit": result.commit,
        "generated_at": result.generated_at,
        "stats": {
            "total_files": len(result.modules),
            "total_lines": sum(m.lines for m in result.modules),
            "total_classes": sum(len(m.classes) for m in result.modules),
            "total_functions": sum(len(m.functions) for m in result.modules),
            "languages": sorted(set(m.language for m in result.modules)),
        },
        "quality_summary": result.quality_summary,
        "security_weights": [
            {
                "file": w.file_path, "total": round(w.total, 2),
                "pagerank": w.pagerank_score, "unsafe": w.unsafe_score,
                "surface": w.surface_score, "quality_penalty": w.quality_penalty,
                "patterns": [
                    {"line": p.line, "name": p.pattern_name, "cwe": p.cwe_id, "severity": p.severity}
                    for p in w.unsafe_patterns
                ],
            }
            for w in sorted(result.weights.values(), key=lambda w: w.total, reverse=True)
        ],
        "modules": {
            m.path: {
                "language": m.language, "lines": m.lines,
                "rank": round(result.ranks.get(_path_to_module(m.path), 0), 4),
                "imports": m.imports,
                "classes": {
                    c.name: {
                        "bases": c.bases, "methods": [me.name for me in c.methods],
                        "fields_count": len(c.fields),
                        "rank": round(result.ranks.get(c.qualified_name, 0), 4),
                    }
                    for c in m.classes
                },
                "functions": {
                    f.name: {"rank": round(result.ranks.get(f.qualified_name, 0), 4)}
                    for f in m.functions
                },
            }
            for m in result.modules
        },
    }


# ============================================================================
# Orchestrator
# ============================================================================


EXCLUDE_DEFAULTS = [
    "obj/", "bin/", "Migrations/", "__pycache__/", ".venv/", "node_modules/",
    ".git/", ".mypy_cache/", ".pytest_cache/", ".ruff_cache/", "*.designer.cs",
    "*.g.cs",
]


def collect_files(
    target_root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[Path]:
    """Collect all Python and C# source files under the target."""
    exclude = exclude or EXCLUDE_DEFAULTS
    extensions = {".py", ".cs"}

    if scope:
        files: list[Path] = []
        for pattern in scope:
            candidate = target_root / pattern
            if candidate.is_file() and candidate.suffix in extensions:
                files.append(candidate)
            elif candidate.is_dir():
                for ext in extensions:
                    files.extend(candidate.rglob(f"*{ext}"))
            elif "*" in pattern:
                files.extend(target_root.glob(pattern))
        files = list(set(files))
    else:
        files = []
        for ext in extensions:
            files.extend(target_root.rglob(f"*{ext}"))

    result = []
    for f in sorted(files):
        rel = str(f.relative_to(target_root))
        if any(_matches_exclude(rel, exc) for exc in exclude):
            continue
        result.append(f)
    return result


def _matches_exclude(rel_path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return rel_path.startswith(pattern) or rel_path.startswith(pattern.rstrip("/"))
    if "*" in pattern or "?" in pattern or "[" in pattern:
        from fnmatch import fnmatch
        return fnmatch(rel_path, pattern) or fnmatch(rel_path.split("/")[-1], pattern)
    return rel_path.startswith(pattern)


def _get_git_commit(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def get_parser(extension: str) -> LanguageParser:
    if extension == ".py":
        return PythonParser()
    if extension == ".cs":
        return CSharpParser()
    raise ValueError(f"No parser for extension: {extension}")


def analyze(
    target_path: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
) -> CodeIntelResult:
    """Run full code intelligence analysis on a target directory."""
    files = collect_files(target_path, scope, exclude)

    # Parse all files with the appropriate parser
    parsers: dict[str, LanguageParser] = {}
    modules: list[ModuleInfo] = []
    all_unsafe: dict[str, list[UnsafePattern]] = {}
    all_metrics: dict[str, FileMetrics] = {}

    for file_path in files:
        ext = file_path.suffix
        if ext not in parsers:
            parsers[ext] = get_parser(ext)
        parser = parsers[ext]
        rel_path = str(file_path.relative_to(target_path))

        module = parser.parse_file(file_path, rel_path)
        if module:
            modules.append(module)

        unsafe = parser.detect_unsafe_patterns(file_path, rel_path)
        if unsafe:
            all_unsafe[rel_path] = unsafe

        metrics = parser.compute_file_metrics(file_path, rel_path)
        if metrics:
            all_metrics[rel_path] = metrics

    # Build cross-reference graph and compute PageRank
    graph = build_reference_graph(modules)
    ranks = compute_pagerank(graph)

    # Compute security weights
    weights: dict[str, SecurityWeight] = {}
    for module in modules:
        module_rank = ranks.get(_path_to_module(module.path), 0.0)
        unsafe_patterns = all_unsafe.get(module.path, [])
        metrics = all_metrics.get(module.path)
        weights[module.path] = compute_security_weight(module, module_rank, unsafe_patterns, metrics)

    # Quality summary
    quality_summary = aggregate_quality_metrics(all_metrics)

    return CodeIntelResult(
        target_path=str(target_path),
        commit=_get_git_commit(target_path),
        generated_at=datetime.datetime.now(datetime.UTC).isoformat(),
        modules=modules,
        graph=graph,
        ranks=ranks,
        metrics=all_metrics,
        unsafe=all_unsafe,
        weights=weights,
        quality_summary=quality_summary,
    )


# ============================================================================
# CLI
# ============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Code Intelligence — structural analysis for security review prioritisation.",
    )
    parser.add_argument(
        "--target", "-t", type=str, default=".",
        help="Path to the codebase to analyze (default: current directory)",
    )
    parser.add_argument(
        "--scope", nargs="*", default=None,
        help="Directories or files to include (default: all Python/C# files)",
    )
    parser.add_argument(
        "--exclude", nargs="*", default=None,
        help="Patterns to exclude (default: obj/, bin/, __pycache__/, .venv/, etc.)",
    )
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--max-tokens", type=int, default=None,
        help="Maximum token budget for output (trims low-priority content)",
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Print summary statistics only",
    )
    parser.add_argument(
        "--weights", action="store_true",
        help="Print security-weight ranking only",
    )
    parser.add_argument(
        "--unsafe", action="store_true",
        help="Print unsafe pattern report only",
    )
    parser.add_argument(
        "--quality", action="store_true",
        help="Print quality metrics report only",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Shortcut for --format json",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Write output to file",
    )
    parser.add_argument(
        "--stdout", action="store_true",
        help="Print to stdout (default if no --output)",
    )

    args = parser.parse_args()
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    result = analyze(target, scope=args.scope, exclude=args.exclude)

    # Focused reports
    if args.stats:
        _print_stats(result)
        return

    if args.weights:
        _print_weights(result)
        return

    if args.unsafe:
        _print_unsafe(result)
        return

    if args.quality:
        _print_quality(result)
        return

    # Full output
    fmt = "json" if args.json_output else args.format
    if fmt == "json":
        output = json.dumps(render_json(result), indent=2)
    else:
        output = render_markdown(result, max_tokens=args.max_tokens)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"Code intel written to {out_path} ({len(result.modules)} files, ~{_estimate_tokens(output):,} tokens)")
    else:
        print(output)


def _print_stats(result: CodeIntelResult) -> None:
    languages = sorted(set(m.language for m in result.modules))
    py_files = sum(1 for m in result.modules if m.language == "python")
    cs_files = sum(1 for m in result.modules if m.language == "csharp")

    print(f"Target:     {result.target_path}")
    print(f"Commit:     {result.commit[:12] if result.commit else 'unknown'}")
    print(f"Languages:  {', '.join(languages)}")
    print(f"Files:      {len(result.modules)} (Python: {py_files}, C#: {cs_files})")
    print(f"Lines:      {sum(m.lines for m in result.modules):,}")
    print(f"Classes:    {sum(len(m.classes) for m in result.modules)}")
    print(f"Functions:  {sum(len(m.functions) for m in result.modules)}")
    print(f"Graph:      {len(result.graph.nodes)} nodes, {len(result.graph.edges)} edges")

    all_unsafe = sum(len(p) for p in result.unsafe.values())
    critical = sum(1 for ps in result.unsafe.values() for p in ps if p.severity == "CRITICAL")
    print(f"Unsafe:     {all_unsafe} patterns ({critical} CRITICAL)")

    qs = result.quality_summary
    print(f"\nQuality:    doc={qs.get('doc_coverage', 0):.0%}  "
          f"types={qs.get('param_type_coverage', 0):.0%}  "
          f"exceptions={qs.get('exception_handler_quality', 0):.0%}")

    top = sorted(result.weights.values(), key=lambda w: w.total, reverse=True)[:5]
    print("\nTop 5 security priority:")
    for w in top:
        print(f"  {w.total:.1f}  {w.file_path}")


def _print_weights(result: CodeIntelResult) -> None:
    sorted_weights = sorted(result.weights.values(), key=lambda w: w.total, reverse=True)
    print(f"{'Weight':>7}  {'PR':>5}  {'Unsafe':>6}  {'Surface':>7}  {'Quality':>7}  File")
    print("-" * 70)
    for w in sorted_weights:
        print(
            f"{w.total:>7.1f}  {w.pagerank_score:>5.2f}  {w.unsafe_score:>6.2f}  "
            f"{w.surface_score:>7.2f}  {w.quality_penalty:>7.2f}  {w.file_path}"
        )


def _print_unsafe(result: CodeIntelResult) -> None:
    all_unsafe = [p for patterns in result.unsafe.values() for p in patterns]
    if not all_unsafe:
        print("No unsafe patterns detected.")
        return

    all_unsafe.sort(key=lambda p: (p.severity != "CRITICAL", p.severity != "HIGH", p.file_path))
    print(f"{'Severity':<10} {'CWE':<8} {'Location':<40} Pattern")
    print("-" * 80)
    for p in all_unsafe:
        loc = f"{p.file_path}:{p.line}"
        print(f"{p.severity:<10} {p.cwe_id:<8} {loc:<40} {p.pattern_name}")
    print(f"\nTotal: {len(all_unsafe)} unsafe patterns")


def _print_quality(result: CodeIntelResult) -> None:
    qs = result.quality_summary
    print("Quality Baseline")
    print("=" * 40)
    print(f"Files analyzed:          {qs.get('file_count', 0)}")
    print(f"Total lines:             {qs.get('total_lines', 0):,}")
    print(f"Doc coverage:            {qs.get('doc_coverage', 0):.1%}")
    print(f"Param type coverage:     {qs.get('param_type_coverage', 0):.1%}")
    print(f"Return type coverage:    {qs.get('return_type_coverage', 0):.1%}")
    print(f"Exception handling:      {qs.get('exception_handler_quality', 0):.1%}")
    print(f"Avg function length:     {qs.get('avg_function_length', 0):.0f} lines")
    print(f"P90 function length:     {qs.get('p90_function_length', 0)} lines")
    print(f"P90 nesting depth:       {qs.get('p90_nesting', 0)}")


if __name__ == "__main__":
    main()
