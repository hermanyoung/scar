"""Data models for code analysis.

Language-agnostic types representing structural and metric information
extracted from source files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SymbolKind(str, Enum):
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    CONSTANT = "constant"
    PROPERTY = "property"


@dataclass
class SymbolInfo:
    """A named symbol in a source file (class, function, method, constant)."""

    name: str
    kind: SymbolKind
    qualified_name: str
    line: int
    end_line: int = 0
    params: list[str] = field(default_factory=list)
    return_type: str = ""
    bases: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    methods: list[SymbolInfo] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)


@dataclass
class FileMetrics:
    """Per-file structural metrics. Language-agnostic output from any parser."""

    path: str
    language: str
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
    naming_violations: int = 0
    unsafe_calls: list[str] = field(default_factory=list)
    public_definitions: int = 0
    private_definitions: int = 0
    # C#-specific robustness signals (defaults for Python)
    nullable_enabled: bool = False
    null_forgiving_count: int = 0
    sealed_classes: int = 0

    @property
    def type_coverage(self) -> float:
        total = self.total_params + self.total_returns
        annotated = self.annotated_params + self.annotated_returns
        return annotated / total if total > 0 else 1.0

    @property
    def avg_function_length(self) -> float:
        if not self.function_lengths:
            return 0.0
        return sum(self.function_lengths) / len(self.function_lengths)


@dataclass
class ModuleInfo:
    """Structural information for dependency graph construction."""

    path: str
    language: str
    lines: int
    imports: list[str]
    classes: list[SymbolInfo]
    functions: list[SymbolInfo]
    constants: list[str]
    references: list[str] = field(default_factory=list)


@dataclass
class FileResult:
    """Combined output from a single file parse.

    Metrics are always populated. Module is only populated when
    structural analysis is requested (for graph building).
    """

    metrics: FileMetrics
    module: ModuleInfo | None = None


@dataclass(frozen=True)
class ReferenceEdge:
    """A directed edge in the dependency graph."""

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
    """Dependency graph of modules and symbols."""

    nodes: list[str]
    edges: list[ReferenceEdge]


@dataclass
class ProjectMetrics:
    """Aggregate analysis result for a codebase."""

    files: list[FileMetrics] = field(default_factory=list)
    modules: list[ModuleInfo] = field(default_factory=list)
    graph: ReferenceGraph | None = None
    ranks: dict[str, float] = field(default_factory=dict)
    test_files: int = 0
    test_lines: int = 0
    source_files: int = 0
    source_lines: int = 0
