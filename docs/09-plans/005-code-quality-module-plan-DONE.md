# Plan 005: Code Quality Module

**Date:** 3 May 2026
**Status:** [x] Implemented
**Scope:** Build `src/code_analysis/` (shared structural analysis) and `src/code_quality/` (scoring engine). Expose as a `quality` command in `security-review.py`. Leave existing scripts untouched.
**Disposition (2026-07-06):** Test gaps (C# parser fixtures/tests) closed by plan 019 WP-G.

---

## 1. Problem Statement

We need a code quality scorer that works for both Python and C# codebases. The logic exists in `scripts/code_quality.py` (scoring) and `scripts/code_intel.py` (parsers, metrics, graph), but:

- Both are monolithic scripts, not importable modules
- They duplicate file collection, metric extraction, and unsafe pattern detection
- Neither is structured for reuse by other consumers (pipeline, CI, other tools)
- C# parsing is fully implemented in `code_intel.py` but not available to quality scoring

**Decision:** Build two new modules fresh in `src/`, porting proven logic. Don't move or modify existing scripts — they keep working as-is.

---

## 2. Target Architecture

```
src/
├── code_analysis/              ← Shared structural analysis layer
│   ├── __init__.py             ← Public API: analyze(), FileMetrics, ProjectMetrics
│   ├── models.py              ← FileMetrics, ModuleInfo, ProjectMetrics, ReferenceGraph
│   ├── collect.py             ← File discovery (ONE implementation, replaces 3 copies)
│   ├── parsers/
│   │   ├── __init__.py        ← LanguageParser protocol + registry
│   │   ├── python.py          ← Python AST parser (ported from code_intel.py)
│   │   └── csharp.py          ← C# tree-sitter parser (ported from code_intel.py)
│   └── graph.py               ← Reference graph + PageRank (ported from code_intel.py)
│
├── code_quality/               ← Scoring engine (pure math)
│   ├── __init__.py             ← Public API: score_project(), PQIResult
│   ├── models.py              ← DimensionScore, PQIResult, QualityBand, QualityIssue
│   ├── scoring.py             ← Normalizers + 7 dimension scorers + composite
│   └── tools.py               ← Bandit/Radon runners (optional enrichment)
│
└── security_review/            ← EXISTING, unchanged for now
```

### Dependency Graph (DAG, no cycles)

```
code_analysis          (no imports from src/)
      ↑
code_quality           (imports code_analysis for metrics)
      ↑
security_review        (can later import either — separate plan)
```

### What Stays Unchanged

- `scripts/code_intel.py` — standalone dev tool, untouched
- `scripts/code_quality.py` — standalone dev tool, untouched
- `scripts/code_map.py` — standalone dev tool, untouched
- `src/security_review/` — no changes in this plan

The scripts serve a different purpose (quick dev-time analysis, ad-hoc runs). The `src/` modules are the proper importable packages for programmatic use and CLI integration.

---

## 3. Module 1: `src/code_analysis/`

The shared foundation. Parses source files, extracts metrics, builds dependency graphs. Language-agnostic interface with pluggable parsers.

### 3.1 Interface (`__init__.py`)

```python
from code_analysis.models import FileMetrics, ProjectMetrics, ModuleInfo
from code_analysis.collect import collect_files
from code_analysis.parsers import get_parser, list_languages

def analyze(
    target: Path,
    *,
    files: list[Path] | None = None,   # pre-discovered list (skip collection)
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    languages: list[str] | None = None, # filter to specific languages
    include_graph: bool = False,        # build reference graph (slower)
) -> ProjectMetrics:
    """Analyze a codebase. Main entry point.

    If `files` is provided, skips file discovery (caller controls scope).
    If `files` is None, discovers files using scope/exclude patterns.
    """
```

**Design decisions:**
- `files` parameter allows callers to provide a pre-discovered list (pipeline uses this — single source of truth for file scope)
- `include_graph=False` by default — graph + PageRank is expensive, only enable when needed (modularity scoring, structural overview)
- Returns `ProjectMetrics` — a complete analysis result that any consumer can interpret

### 3.2 Models (`models.py`)

```python
@dataclass
class FileMetrics:
    """Per-file structural metrics. Language-agnostic output."""
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
    function_lengths: list[int]
    naming_violations: int = 0
    unsafe_calls: list[str]
    public_definitions: int = 0
    private_definitions: int = 0
    # C#-specific robustness signals (defaults for Python)
    nullable_enabled: bool = False       # #nullable enable directive present
    null_forgiving_count: int = 0        # suppression_expression (!) usage
    sealed_classes: int = 0              # classes with sealed modifier

@dataclass
class ModuleInfo:
    """Structural info for dependency graph construction."""
    path: str
    language: str
    lines: int
    imports: list[str]
    classes: list[SymbolInfo]
    functions: list[SymbolInfo]
    constants: list[str]
    references: list[str]

@dataclass
class ProjectMetrics:
    """Aggregate analysis result."""
    files: list[FileMetrics]
    modules: list[ModuleInfo]       # populated when include_graph=True
    graph: ReferenceGraph | None    # populated when include_graph=True
    ranks: dict[str, float]         # PageRank scores (empty if no graph)
    test_files: int = 0
    test_lines: int = 0
    source_files: int = 0
    source_lines: int = 0
```

### 3.3 File Collection (`collect.py`)

**ONE implementation** replacing the 3 copies in code_quality.py, code_map.py, and code_intel.py.

```python
def collect_files(
    root: Path,
    *,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    extensions: set[str] | None = None,  # e.g. {".py", ".cs"}
) -> list[Path]:
    """Discover source files under root.

    Args:
        scope: Directory/glob patterns to include. None = entire root.
        exclude: Patterns to skip (directories, globs).
        extensions: File extensions to include. None = all known languages.
    """
```

Ported from `scripts/code_intel.py`'s `_collect_files()` with the addition of the `extensions` filter.

### 3.4 Parsers (`parsers/`)

#### Protocol (`parsers/__init__.py`)

```python
from typing import Protocol

@dataclass
class FileResult:
    """Combined output from a single file parse."""
    metrics: FileMetrics
    module: ModuleInfo | None = None  # only populated when structure requested

class LanguageParser(Protocol):
    @property
    def language(self) -> str: ...

    @property
    def extensions(self) -> set[str]: ...

    def analyze_file(
        self, file_path: Path, rel_path: str, *, include_structure: bool = False,
    ) -> FileResult | None:
        """Parse a file ONCE. Extract metrics always, structure on request.

        Returns None on parse failure (SyntaxError, unreadable file).
        When include_structure=True, also populates FileResult.module
        for graph construction.
        """


def get_parser(language: str) -> LanguageParser:
    """Get parser by language name. Raises ValueError if unavailable."""

def list_languages() -> list[str]:
    """List available parser languages."""
```

**Why a single method:** The parser reads and parses the file once. Both metrics and structural info come from the same syntax tree. Two separate methods would parse every file twice — wasteful for tree-sitter, unnecessary for ast. The `include_structure` flag controls whether to do the extra work of extracting imports, class hierarchies, and function signatures for graph building.

#### Python Parser (`parsers/python.py`)

Ported from `code_intel.py` `PythonParser` (lines 207-489). Implements `analyze_file()` with a single `ast.parse()` call. Uses stdlib `ast` — no external dependencies.

Key internal methods:
- `_extract_metrics(tree)` — callable counts, params, nesting, naming, unsafe patterns
- `_extract_structure(tree)` — imports, classes, functions, constants (only when `include_structure=True`)
- `_analyze_callable()`, `_analyze_except_handler()`
- `_compute_max_nesting()`
- `_detect_unsafe_patterns()` — returns description strings for `FileMetrics.unsafe_calls`
- `_count_naming_violations()` — snake_case enforcement

#### C# Parser (`parsers/csharp.py`)

Ported from `code_intel.py` `CSharpParser` (lines 497-746). Implements `analyze_file()` with a single `tree.parse()` call. Uses `tree-sitter` + `tree-sitter-c-sharp`.

Key internal methods:
- `_extract_metrics(root, source)` — nesting, method lengths, accessibility, catch clauses, XML doc comments, nullable/sealed signals
- `_extract_structure(root, source)` — using directives, classes, namespaces (only when `include_structure=True`)
- `_detect_unsafe_patterns()` — BinaryFormatter, Process.Start, SQL concat, TypeNameHandling
- `_compute_nesting()` — if/for/foreach/while/using/try depth

**C#-specific metric extraction:**
- `nullable_enabled` — scans for `#nullable enable` directive
- `null_forgiving_count` — counts `suppression_expression` nodes (`!`)
- `sealed_classes` — counts classes with `sealed` modifier

**Graceful degradation:** If tree-sitter is not installed, `get_parser("csharp")` raises `ValueError` with install instructions. The caller handles this (quality scoring falls back to Python-only or errors clearly).

### 3.5 Graph (`graph.py`)

Ported from `code_intel.py` (lines 900-1063):
- `build_reference_graph(modules: list[ModuleInfo]) -> ReferenceGraph`
- `compute_pagerank(graph: ReferenceGraph) -> dict[str, float]`
- Helper functions: `_build_module_index`, `_build_symbol_index`, `_resolve_import`, etc.

Only called when `analyze(include_graph=True)`.

---

## 4. Module 2: `src/code_quality/`

Pure scoring engine. Takes `ProjectMetrics` in, produces `PQIResult` out. No file I/O, no subprocess calls, no parsing.

### 4.1 Interface (`__init__.py`)

```python
from code_quality.models import PQIResult, QualityBand, DimensionScore
from code_quality.scoring import compute_pqi, WEIGHT_PROFILES

def score_project(
    target: Path,
    *,
    language: str | None = None,     # None = auto-detect
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    profile: str = "production",
    tools: list[str] | None = None,  # None = auto-detect available
    include_graph: bool = True,      # needed for modularity dimension
) -> PQIResult:
    """Score a codebase's quality. Main entry point.

    Orchestrates: collect files → analyze (code_analysis) → run tools → score.
    """
```

This is the only function with I/O — it calls `code_analysis.analyze()` and optionally runs external tools. Everything else in the package is pure.

### 4.2 Models (`models.py`)

```python
class QualityBand(str, Enum):
    POOR = "Poor"              # 0-30
    ACCEPTABLE = "Acceptable"  # 31-54
    ADEQUATE = "Adequate"      # 55-64
    GOOD = "Good"              # 65-79
    EXCELLENT = "Excellent"    # 80-100

@dataclass
class DimensionScore:
    name: str
    score: float                        # 0-100
    sub_scores: dict[str, float]
    confidence: float = 1.0             # 0-1, lower when tools unavailable
    recommendations: list[str]

@dataclass
class PQIResult:
    composite: float                    # 0-100
    dimensions: dict[str, DimensionScore]
    quality_band: QualityBand
    floor_penalty: float                # 1.0 = no penalty
    file_count: int
    line_count: int

WEIGHT_PROFILES: dict[str, dict[str, float]]  # production, library, safety_critical
```

### 4.3 Scoring Engine (`scoring.py`)

Ported from `scripts/code_quality.py` lines 155-920. All pure functions.

```python
# Normalizers
def sigmoid(x: float, midpoint: float, k: float = 0.5) -> float: ...
def exp_decay(count: float, rate: float = 0.5) -> float: ...
def inverse_linear(value: float, good: float, bad: float) -> float: ...
def ratio_score(numerator: float, denominator: float) -> float: ...

# Dimension scorers — each takes ProjectMetrics + optional ToolResults
def score_maintainability(metrics: ProjectMetrics, tools: dict[str, ToolResult]) -> DimensionScore: ...
def score_security(metrics: ProjectMetrics, tools: dict[str, ToolResult]) -> DimensionScore: ...
def score_modularity(metrics: ProjectMetrics) -> DimensionScore: ...
def score_testability(metrics: ProjectMetrics, tools: dict[str, ToolResult]) -> DimensionScore: ...
def score_robustness(metrics: ProjectMetrics) -> DimensionScore: ...
def score_elegance(metrics: ProjectMetrics, tools: dict[str, ToolResult]) -> DimensionScore: ...
def score_reusability(metrics: ProjectMetrics) -> DimensionScore: ...

# Composite
def compute_pqi(dimensions: dict[str, DimensionScore], profile: str) -> PQIResult: ...
```

**Key change from current script:** Dimension scorers receive `ProjectMetrics` (from `code_analysis`) instead of `ProjectAnalysis` (the old internal type). The fields are identical — it's a rename at the interface boundary.

**Modularity dimension:** Uses `metrics.graph` and `metrics.ranks` (from `code_analysis` when `include_graph=True`). If graph is None, returns score=50 with confidence=0.3 (same as current behaviour).

### 4.4 Tools (`tools.py`)

External tool runners for optional enrichment. Each implements:

```python
@dataclass
class ToolResult:
    tool: str
    available: bool
    findings: list[Finding]
    metrics: dict[str, float]
    error: str = ""

class BanditRunner:
    def run(self, root: Path, scope, exclude) -> ToolResult: ...

class RadonRunner:
    def run(self, root: Path, scope, exclude) -> ToolResult: ...
```

Ported from `scripts/code_quality.py` `run_bandit()` and `run_radon()`.

**No `DotnetMetricsRunner` in v1.** C# scoring works with tree-sitter metrics alone. If we add dotnet metrics later, it slots in here without changing anything else.

---

## 5. CLI Command (`security-review.py`)

```python
@cli.command("quality")
@click.option("--target", required=True, type=click.Path(exists=True),
              help="Path to codebase root.")
@click.option("--scope", multiple=True, default=None,
              help="Directories/patterns to include (repeatable).")
@click.option("--exclude", multiple=True, default=None,
              help="Patterns to exclude (repeatable).")
@click.option("--language", default=None,
              type=click.Choice(["python", "csharp", "auto"]),
              help="Language (default: auto-detect).")
@click.option("--profile", default="production",
              type=click.Choice(["production", "library", "safety_critical"]),
              help="Weight profile.")
@click.option("--json", "json_output", is_flag=True,
              help="JSON output to stdout.")
@click.option("--recommendations", is_flag=True,
              help="Show improvement recommendations.")
@click.option("--no-tools", is_flag=True,
              help="Skip external tools (AST/tree-sitter only).")
@click.option("--output", "-o", default=None,
              help="Write JSON to file.")
def quality(target, scope, exclude, language, profile, json_output,
            recommendations, no_tools, output):
    """Score codebase quality using the PyQuality Index (PQI)."""
    from code_quality import score_project

    result = score_project(
        target=Path(target).resolve(),
        language=language if language != "auto" else None,
        scope=list(scope) or None,
        exclude=list(exclude) or None,
        profile=profile,
        tools=[] if no_tools else None,
    )

    if json_output or output:
        data = result_to_dict(result)
        if output:
            Path(output).write_text(json.dumps(data, indent=2))
            click.echo(f"Written to {output}")
        else:
            click.echo(json.dumps(data, indent=2))
    else:
        print_report(result, show_recommendations=recommendations)
```

### Language Auto-Detection

In `score_project()`:
1. Run `collect_files()` with extensions={".py", ".cs"}
2. Count by extension
3. If >90% one language → use that parser
4. If mixed → run both parsers, merge into single `ProjectMetrics`

---

## 6. What We Port vs. What We Write Fresh

### Ported from `scripts/code_intel.py` (proven logic, new structure)

| Source | Destination | Lines |
|---|---|---|
| `PythonParser.parse_file()` + helpers | `code_analysis/parsers/python.py` | ~180 |
| `PythonParser.compute_file_metrics()` + helpers | `code_analysis/parsers/python.py` | ~120 |
| `CSharpParser` (full implementation) | `code_analysis/parsers/csharp.py` | ~250 |
| `build_reference_graph()` + `compute_pagerank()` | `code_analysis/graph.py` | ~170 |
| `_collect_files()` | `code_analysis/collect.py` | ~50 |
| `FileMetrics`, `ModuleInfo`, `SymbolInfo`, `ReferenceGraph` | `code_analysis/models.py` | ~80 |

### Ported from `scripts/code_quality.py` (proven logic, new structure)

| Source | Destination | Lines |
|---|---|---|
| Normalizers (sigmoid, exp_decay, etc.) | `code_quality/scoring.py` | ~30 |
| 7 dimension scorers | `code_quality/scoring.py` | ~280 |
| `compute_pqi()` + floor penalty | `code_quality/scoring.py` | ~40 |
| Weight profiles | `code_quality/scoring.py` | ~30 |
| `run_bandit()`, `run_radon()` | `code_quality/tools.py` | ~180 |
| `PQIResult`, `DimensionScore`, `QualityBand` | `code_quality/models.py` | ~60 |

### Written Fresh

| What | Where | Lines |
|---|---|---|
| `analyze()` orchestrator | `code_analysis/__init__.py` | ~50 |
| `score_project()` orchestrator | `code_quality/__init__.py` | ~60 |
| `LanguageParser` protocol + registry | `code_analysis/parsers/__init__.py` | ~40 |
| CLI `quality` command | `security-review.py` | ~50 |
| Terminal output (Rich) | `code_quality/__init__.py` or separate | ~60 |

**Total new code:** ~320 lines of fresh orchestration/glue
**Total ported code:** ~1270 lines of proven logic in new structure

---

## 7. C# Robustness Dimension — Adjusted Signals

The current Robustness scorer measures "type annotation coverage" — which is 100% for C# (statically typed). For C#, we measure different signals:

| Signal | What it means | How detected |
|---|---|---|
| Nullable annotation ratio | Files with `#nullable enable` vs without | Directive presence in source |
| Null-forgiving operator (`!`) count | Bypassing null safety | `suppression_expression` nodes |
| Exception handling quality | Same as Python — bare catch, broad catch | `catch_clause` analysis |
| Sealed ratio | Properly sealed classes vs open inheritance | `sealed` modifier on class declarations |

The scoring function checks `metrics.language` and applies the appropriate sub-scorers:

```python
def score_robustness(metrics: ProjectMetrics) -> DimensionScore:
    source = _source_files(metrics)
    if not source:
        return DimensionScore(name="Robustness", score=50.0, ...)

    # Language-agnostic: exception handling quality
    handler_quality = _score_exception_handling(source)

    # Language-specific: type safety signals
    if _primary_language(source) == "csharp":
        type_safety = _score_csharp_type_safety(source)
    else:
        type_safety = _score_python_type_coverage(source)

    score = type_safety * 0.65 + handler_quality * 0.35
    ...
```

---

## 8. Edge Cases & Error Handling

| Scenario | Behaviour |
|---|---|
| Target path has 0 parseable files | Return `PQIResult(composite=0.0, quality_band=POOR)` with recommendation: "No parseable source files found" |
| All files fail to parse (SyntaxError) | Same as above — `analyze()` returns empty `ProjectMetrics` |
| `--language csharp` but tree-sitter not installed | Raise clear error: "C# analysis requires tree-sitter. Install with: `pip install tree-sitter tree-sitter-c-sharp`" |
| Mixed codebase (e.g. 10 Python + 500 C#) | Auto-detect uses the majority language; `--language auto` explicitly runs both parsers and merges metrics |
| Bandit/Radon not installed | `ToolResult(available=False)` — scoring proceeds with lower confidence (no crash) |
| File unreadable (permissions, encoding) | `analyze_file()` returns None — file skipped silently, counted in no metrics |
| `include_graph=True` but only 1 file | Graph is trivially empty — modularity scores 50.0 with confidence 0.3 |
| Empty directory (exists but no files) | Same as 0 files — composite 0.0, band POOR |

**Principle:** Never crash on bad input. Degrade gracefully with lower confidence scores and clear recommendations explaining what's missing.

---

## 9. Testing Strategy

### Unit Tests — `tests/unit/test_code_analysis/`

| Test file | What it validates |
|---|---|
| `test_collect.py` | File discovery with scope/exclude/extensions |
| `test_python_parser.py` | Metric extraction on fixture files |
| `test_csharp_parser.py` | Metric extraction on C# fixture files |
| `test_graph.py` | Reference graph + PageRank on synthetic modules |
| `test_analyze.py` | Full `analyze()` orchestration |

### Unit Tests — `tests/unit/test_code_quality/`

| Test file | What it validates |
|---|---|
| `test_normalizers.py` | Sigmoid, exp_decay, inverse_linear at known inputs |
| `test_dimensions.py` | Each dimension scorer with synthetic `ProjectMetrics` |
| `test_composite.py` | Geometric mean, floor penalty, band classification |
| `test_tools.py` | BanditRunner/RadonRunner with mocked subprocess |
| `test_score_project.py` | Full orchestration on test fixtures |

### Test Fixtures

```
tests/unit/test_code_analysis/fixtures/
    python/
        clean.py            # Well-typed, documented, shallow nesting
        complex.py          # Deep nesting, long functions, bare excepts
        unsafe.py           # eval, pickle, os.system
    csharp/
        Clean.cs            # XML docs, sealed, nullable enabled
        Complex.cs          # Deep nesting, catch-all, no docs
        Unsafe.cs           # BinaryFormatter, Process.Start, SQL concat
```

### Black Box Validation

```python
def test_parser_produces_valid_metrics():
    """Any parser implementation produces structurally valid FileMetrics."""
    for parser in [PythonParser(), CSharpParser()]:
        for fixture in get_fixtures(parser.language):
            result = parser.analyze_file(fixture, fixture.name)
            assert result is not None
            assert result.metrics.lines > 0
            assert result.metrics.max_nesting >= 0
            assert len(result.metrics.function_lengths) == result.metrics.functions

def test_scoring_is_deterministic():
    """Same input always produces same score."""
    metrics = make_synthetic_project()
    r1 = compute_pqi(score_all_dimensions(metrics), "production")
    r2 = compute_pqi(score_all_dimensions(metrics), "production")
    assert r1.composite == r2.composite
```

### Replacement Test

```python
def test_analyzer_is_swappable():
    """Scoring works identically regardless of which parser produced the metrics."""
    # Create identical metrics as if from Python vs C#
    py_metrics = ProjectMetrics(files=[...], source_files=5, source_lines=500)
    cs_metrics = ProjectMetrics(files=[...], source_files=5, source_lines=500)

    py_result = compute_pqi(score_all_dimensions(py_metrics), "production")
    cs_result = compute_pqi(score_all_dimensions(cs_metrics), "production")

    # Same metrics → same score, regardless of language origin
    assert py_result.composite == cs_result.composite
```

---

## 10. Implementation Steps

### Phase 1: `src/code_analysis/` Foundation

1. Create `src/code_analysis/models.py` — dataclasses (FileMetrics, ModuleInfo, SymbolInfo, ProjectMetrics, ReferenceGraph)
2. Create `src/code_analysis/collect.py` — file discovery
3. Create `src/code_analysis/parsers/__init__.py` — protocol + registry
4. Create `src/code_analysis/parsers/python.py` — port from code_intel.py PythonParser
5. Create `src/code_analysis/parsers/csharp.py` — port from code_intel.py CSharpParser
6. Create `src/code_analysis/graph.py` — port reference graph + PageRank
7. Create `src/code_analysis/__init__.py` — `analyze()` orchestrator
8. Write unit tests for each component
9. Verify: `pytest tests/unit/test_code_analysis/ -v` passes

### Phase 2: `src/code_quality/` Scoring

10. Create `src/code_quality/models.py` — scoring-specific types
11. Create `src/code_quality/scoring.py` — port normalizers + dimension scorers + composite
12. Create `src/code_quality/tools.py` — port Bandit/Radon runners
13. Create `src/code_quality/__init__.py` — `score_project()` orchestrator
14. Write unit tests for scoring (synthetic data, no I/O)
15. Verify: `pytest tests/unit/test_code_quality/ -v` passes

### Phase 3: CLI Integration

16. Add `quality` command to `security-review.py`
17. Add terminal output (Rich table + bar chart)
18. Test CLI on this repo and a C# target
19. Verify: `python security-review.py quality --target . --no-tools` works

### Phase 4: Validation

20. Run quality scoring on this repo — compare output to current `scripts/code_quality.py`
21. Run quality scoring on a C# project — verify C# dimensions produce reasonable scores
22. Run full test suite: `pytest tests/unit/ -v` (no regressions)

---

## 11. What NOT to Build

- No `DotnetMetricsRunner` in v1 — tree-sitter metrics are sufficient
- No pipeline integration — separate future plan when security_review wants to consume these
- No `scripts/code_intel.py` migration — stays untouched
- No git-blame or coverage analysis — out of scope
- No file watcher or daemon mode
- No CI integration (GitHub Actions output) — future enhancement

---

## 12. Success Criteria

1. `python security-review.py quality --target .` produces valid PQI for this Python repo
2. `python security-review.py quality --target /path/to/csharp --language csharp` works
3. `from code_analysis import analyze` works from any Python script
4. `from code_quality import score_project` works from any Python script
5. Zero imports from `security_review` in either new module
6. Zero imports between `code_analysis` and `code_quality` except `code_quality → code_analysis`
7. All existing tests pass (`pytest tests/unit/ -v`)
8. New tests pass with >90% coverage of `scoring.py`
9. `scripts/code_quality.py` untouched — still works independently

---

## 13. Rollback

- Delete `src/code_analysis/` and `src/code_quality/` — nothing else is affected
- Revert the `quality` command from `security-review.py` (one click group removal)
- Scripts are untouched throughout — no revert needed there

No data migration. No schema changes. No impact on existing pipeline.
