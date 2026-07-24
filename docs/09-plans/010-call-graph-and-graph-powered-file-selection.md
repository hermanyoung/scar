# Plan 010 — Call Graph and Graph-Powered File Selection

**Date:** 2026-05-12
**Status:** Implemented (merged to main 2026-07-17)
**Research:** [007-PostgreSQL-ApacheAGE-pgvector.md](../98-research/007-PostgreSQL-ApacheAGE-pgvector.md)
**Spec:** [001-security-code-review-module-spec.md](../98-research/001-security-code-review-module-spec.md)

---

## Problem

SCAR's CWE-driven holistic pass (Pass 4) selects files by matching keywords in file paths against a static dictionary (`_FILE_TYPE_MATCHERS` in `src/security_review/checks.py`). This has three concrete failures:

1. **Keyword misses.** A repository with `Infrastructure/Persistence/UserStore.cs` is invisible to CWE-89 (SQL Injection) because the keyword matcher looks for "models", "repositories", "dal", "data" — none of which appear in the path. The fallback (security_weight >= 3) is a blunt instrument that pulls in unrelated files and wastes token budget.

2. **No cross-file data flow.** The existing `ReferenceGraph` in `src/code_analysis/graph.py` has import-level and type-reference edges but no method-level CALLS edges. SCAR cannot trace that `UserController.CreateUser(name)` → `UserService.Save(name)` → `UserStore.Insert(name)` → raw SQL. The LLM must reason about this chain from inlined source code — but only if all three files happen to be selected.

3. **No cross-run memory.** Every run rediscovers the entire codebase from scratch. There is no way to say "only re-check CWEs affected by the 5 files that changed" or "this finding was first seen 3 runs ago."

## Solution

Build a method-level call graph using pyan3 (Python) and a Roslyn-based tool (C#). Use the call graph for taint-aware file selection: walk backwards from known sinks or forwards from entry points to find the files that matter for each CWE. Persist the graph and findings in SQLite for cross-run incrementalism.

**Decision:** Do NOT use PostgreSQL + Apache AGE. The research (007) found that AGE has no Homebrew formula, variable-length path queries bypass indexes (Trendyol Apr 2026 report), the Python 3.13 driver is broken (issue #2368), and psycopg3 has a transaction footgun. At SCAR's scale (5k files, 50k symbols, 200k edges), in-memory traversal with rustworkx completes in <100ms — 1000x faster than a single LLM call. SQLite provides persistence without installation overhead.

---

## Architecture

```
BEFORE (current):
  Pass 1 → FileManifest → checks.py:select_files_for_check(keywords) → context_builder.py → LLM

AFTER:
  Pass 0 (new) → parse call graph → persist to SQLite → build in-memory graph
  Pass 1 → FileManifest (unchanged)
  Pass 4 → checks.py:select_files_for_cwe(graph walk) → rank by PageRank → context_builder.py → LLM
```

### New modules

| Module | Location | Purpose |
|---|---|---|
| `call_graph.py` | `src/code_analysis/call_graph.py` | Build method-level call graph from pyan3 + Roslyn outputs |
| `sinks.py` | `src/code_analysis/sinks.py` | Classify methods as sinks/entry-points from decorators + known patterns |
| `walk.py` | `src/code_analysis/walk.py` | BFS/DFS graph walks: backward from sinks, forward from entry points |
| `store.py` | `src/code_analysis/store.py` | SQLite persistence: graph, findings, file cache |
| `roslyn_callgraph/` | `tools/roslyn-callgraph/` | .NET 8 tool that emits call edges as JSON |

### Modified modules

| Module | Changes |
|---|---|
| `src/code_analysis/models.py` | Add `CallEdge` dataclass, extend `SymbolInfo` with `is_entry_point`, `is_sink`, `decorators` |
| `src/code_analysis/graph.py` | Accept call edges alongside import/type edges; expose rustworkx graph |
| `src/security_review/checks.py` | Replace `select_files_for_check()` with graph-walk-based `select_files_for_cwe()` |
| `src/security_review/context_builder.py` | Accept PageRank scores; sort files by rank before token-budget truncation |
| `src/security_review/passes/holistic.py` | Pass the graph to file selection; log selection method used |
| `config/taxonomy/cwe.yaml` | Add `walk_direction`, `max_hops`, `sink_patterns`, `source_patterns` per CWE |
| `pyproject.toml` | Add `pyan3>=2.6`, `rustworkx>=0.15` |

---

## Phase 0 — Call Graph Extraction (Week 1, Days 1-3)

### Task 0.1 — Add `CallEdge` to models

**File:** `src/code_analysis/models.py`

Add after the existing `ReferenceEdge` dataclass:

```python
@dataclass(frozen=True)
class CallEdge:
    """A method-level call relationship."""
    caller: str          # qualified_name of calling method/function
    callee: str          # qualified_name of called method/function
    file_path: str       # file containing the call site
    line: int            # line number of the call site
    confidence: float    # 1.0=fully resolved, 0.5=heuristic, 0.0=wildcard
    kind: str            # "direct", "virtual", "extension", "dynamic"

    def __hash__(self) -> int:
        return hash((self.caller, self.callee, self.line))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallEdge):
            return NotImplemented
        return (self.caller == other.caller
                and self.callee == other.callee
                and self.line == other.line)
```

Extend `SymbolInfo` with three new fields (all with defaults to preserve backward compatibility):

```python
@dataclass
class SymbolInfo:
    # ... existing fields ...
    is_entry_point: bool = False   # has HTTP handler decorator
    is_sink: bool = False          # known dangerous method
    cwe_tags: list[str] = field(default_factory=list)  # e.g. ["CWE-89", "CWE-502"]
```

Add `CallGraph` to hold the full result:

```python
@dataclass
class CallGraph:
    """Method-level call graph for taint analysis."""
    nodes: list[str]                          # qualified_names
    call_edges: list[CallEdge]
    reference_edges: list[ReferenceEdge]      # existing import/type edges
    entry_points: list[str]                   # qualified_names with is_entry_point
    sinks: dict[str, list[str]]               # qualified_name → list of CWE IDs
    file_symbols: dict[str, list[str]]        # file_path → list of qualified_names
    symbol_files: dict[str, str]              # qualified_name → file_path
```

**Tests:** `tests/unit/test_code_analysis/test_models.py` — verify CallEdge hashing, equality, CallGraph construction.

### Task 0.2 — Python call graph via pyan3

**File:** `src/code_analysis/call_graph.py`

```python
"""Build method-level call graphs from source files."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import structlog

from code_analysis.models import CallEdge, CallGraph, ModuleInfo, SymbolInfo
from code_analysis.sinks import classify_sinks, classify_entry_points

logger = structlog.get_logger()


def build_python_call_edges(
    root: Path,
    python_files: list[Path],
) -> list[CallEdge]:
    """Extract call edges from Python files using pyan3.

    pyan3 uses Python's ast + symtable for MRO-aware attribute lookup,
    super() resolution, and self.a = MyClass() tracking.
    Confidence: 1.0 for fully-resolved, 0.5 for partially-resolved.
    """
    if not python_files:
        return []

    try:
        import pyan
    except ImportError:
        logger.warning("call_graph.pyan3_not_installed",
                       hint="pip install pyan3>=2.6")
        return []

    rel_paths = [str(f.relative_to(root)) for f in python_files]
    abs_paths = [str(f) for f in python_files]

    try:
        graph = pyan.create_callgraph(
            filenames=abs_paths,
            root=str(root),
        )
    except Exception as e:
        logger.warning("call_graph.pyan3_failed", error=str(e))
        return []

    edges: list[CallEdge] = []
    for node in graph.nodes:
        for edge in node.out_edges:
            caller_qn = _pyan_node_to_qualified_name(edge.source)
            callee_qn = _pyan_node_to_qualified_name(edge.target)
            if caller_qn and callee_qn:
                edges.append(CallEdge(
                    caller=caller_qn,
                    callee=callee_qn,
                    file_path=_pyan_node_to_file(edge.source, root),
                    line=getattr(edge, 'lineno', 0),
                    confidence=getattr(edge, 'confidence', 0.5),
                    kind="direct",
                ))
    logger.info("call_graph.python_edges", count=len(edges))
    return edges
```

**Note:** pyan3's API may differ from the above — the implementer must read pyan3 v2.6 source to confirm the correct programmatic API. The key contract is: given a list of Python files, return a list of `CallEdge` objects. If pyan3's API doesn't expose per-edge confidence or line numbers, set `confidence=0.7` and `line=0` for all edges.

**Fallback:** If pyan3 fails on a file (syntax error, exotic plugin), fall back to tree-sitter call-site extraction for that file only. Tree-sitter can extract `(call function: [(identifier) (attribute attribute: (identifier))]) @call` but cannot resolve targets — set `confidence=0.3` for these edges.

**Tests:** `tests/unit/test_code_analysis/test_call_graph.py`
- Test with a fixture of 3 Python files with known call chains
- Verify edges are extracted with correct caller/callee qualified names
- Verify fallback to tree-sitter when pyan3 is not installed (mock ImportError)
- Verify empty input returns empty list

### Task 0.3 — C# call graph via Roslyn tool

**Directory:** `tools/roslyn-callgraph/`

Create a minimal .NET 8 console app:

```
tools/roslyn-callgraph/
├── roslyn-callgraph.csproj
└── Program.cs
```

**`roslyn-callgraph.csproj`:**
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Build.Locator" Version="1.7.8" />
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp.Workspaces" Version="4.12.0" />
    <PackageReference Include="Microsoft.CodeAnalysis.Workspaces.MSBuild" Version="4.12.0" />
  </ItemGroup>
</Project>
```

**`Program.cs`:**
The tool accepts a .sln or .csproj path and an output JSON path. For each `InvocationExpressionSyntax` in each syntax tree, it resolves the caller (`GetEnclosingSymbol`) and callee (`GetSymbolInfo`) using the Roslyn semantic model. Output is a JSON array of objects:

```json
[
  {
    "caller": "global::MyApp.Controllers.UserController.CreateUser(string)",
    "callee": "global::MyApp.Services.UserService.Save(string)",
    "file": "src/Controllers/UserController.cs",
    "line": 45,
    "isVirtual": false,
    "isExtension": false
  }
]
```

Use `SymbolDisplayFormat.FullyQualifiedFormat` for both caller and callee. Strip the `global::` prefix when converting to SCAR qualified names.

**Integration in `call_graph.py`:**

```python
def build_csharp_call_edges(
    root: Path,
    solution_or_project: Path,
) -> list[CallEdge]:
    """Extract call edges from C# files using the Roslyn callgraph tool.

    Requires .NET 8 runtime. The tool is optional — if not found or if
    it fails, returns an empty list with a warning.
    """
    tool_path = _find_roslyn_tool()
    if tool_path is None:
        logger.warning("call_graph.roslyn_tool_not_found",
                       hint="Build tools/roslyn-callgraph with 'dotnet build'")
        return []

    output_path = root / ".scar" / "roslyn-callgraph.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            [str(tool_path), str(solution_or_project), str(output_path)],
            capture_output=True, text=True, timeout=300,
            cwd=str(root),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning("call_graph.roslyn_tool_failed", error=str(e))
        return []

    if result.returncode != 0:
        logger.warning("call_graph.roslyn_tool_error",
                       stderr=result.stderr[:500])
        return []

    raw = json.loads(output_path.read_text())
    edges: list[CallEdge] = []
    for item in raw:
        caller = item["caller"].removeprefix("global::")
        callee = item["callee"].removeprefix("global::")
        kind = "virtual" if item.get("isVirtual") else "direct"
        if item.get("isExtension"):
            kind = "extension"
        edges.append(CallEdge(
            caller=caller,
            callee=callee,
            file_path=item["file"],
            line=item["line"],
            confidence=0.9 if kind == "direct" else 0.7,
            kind=kind,
        ))
    logger.info("call_graph.csharp_edges", count=len(edges))
    return edges
```

**Important:** This function calls `subprocess.run`, which violates the rule "only `tools/runner.py` calls subprocess." Two options:
- **(A)** Route through `tools/runner.py` — add an `async run_tool(cmd, timeout)` function and call it from the call graph builder. This is the correct approach per AGENTS.md Rule 1.
- **(B)** Make an exception for build-time tooling that runs before the pipeline starts, documented in AGENTS.md.

**Choose option (A).** Add a synchronous `run_tool_sync()` to `tools/runner.py` since call graph building happens before the async pipeline. This keeps subprocess isolation intact.

**Tests:** `tests/unit/test_code_analysis/test_call_graph.py`
- Mock `subprocess.run` to return fixture JSON
- Verify edges are parsed correctly
- Verify `global::` prefix is stripped
- Verify confidence assignment (direct=0.9, virtual=0.7, extension=0.7)
- Verify timeout/failure returns empty list with warning

### Task 0.4 — Sink and entry-point classification

**File:** `src/code_analysis/sinks.py`

This module classifies methods as sinks (dangerous callees) or entry points (HTTP handlers) based on their qualified names, decorators, and known patterns. The patterns come from a new YAML file.

**File:** `config/taxonomy/sinks.yaml`

```yaml
# Sink patterns per CWE per language.
# Used by code_analysis/sinks.py to tag Method vertices.

python:
  sinks:
    CWE-89:
      - "*.execute"          # cursor.execute, connection.execute
      - "sqlalchemy.text"
      - "django.db.connection.cursor"
      - "*.raw"              # Django Manager.raw()
      - "*.extra"            # Django QuerySet.extra()
    CWE-78:
      - "os.system"
      - "os.popen"
      - "subprocess.call"
      - "subprocess.run"     # with shell=True (checked by context)
      - "subprocess.Popen"
    CWE-502:
      - "pickle.loads"
      - "pickle.load"
      - "yaml.load"          # without Loader=SafeLoader
      - "jsonpickle.decode"
      - "shelve.open"
    CWE-22:
      - "builtins.open"      # with user-controlled path
      - "pathlib.Path.open"
      - "shutil.copy"
      - "shutil.move"
  entry_points:
    - "*.route"              # Flask @app.route
    - "*.get"                # FastAPI @router.get
    - "*.post"
    - "*.put"
    - "*.delete"
    - "*.patch"

csharp:
  sinks:
    CWE-89:
      - "*.FromSqlRaw"
      - "*.ExecuteSqlRaw"
      - "*.ExecuteReader"
      - "*.ExecuteNonQuery"
      - "*.ExecuteScalar"
      - "Dapper.SqlMapper.Query"
      - "Dapper.SqlMapper.Execute"
    CWE-502:
      - "BinaryFormatter.Deserialize"
      - "NetDataContractSerializer.ReadObject"
      - "JsonConvert.DeserializeObject"
      - "JavaScriptSerializer.Deserialize"
      - "XmlSerializer.Deserialize"
    CWE-78:
      - "Process.Start"
      - "ProcessStartInfo"
    CWE-22:
      - "System.IO.File.Open"
      - "System.IO.File.ReadAllText"
      - "System.IO.File.WriteAllText"
      - "System.IO.StreamReader"
  entry_points:
    decorators:
      - "HttpGet"
      - "HttpPost"
      - "HttpPut"
      - "HttpDelete"
      - "HttpPatch"
      - "Route"
      - "ApiController"
    base_classes:
      - "ControllerBase"
      - "Controller"
      - "PageModel"          # Razor Pages
```

**`sinks.py` implementation:**

```python
"""Classify methods as sinks or entry points."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

import yaml
import structlog

from code_analysis.models import SymbolInfo

logger = structlog.get_logger()

_SINKS_CONFIG: dict | None = None


def _load_sinks_config() -> dict:
    global _SINKS_CONFIG
    if _SINKS_CONFIG is None:
        config_path = Path(__file__).parent.parent.parent / "config" / "taxonomy" / "sinks.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"Sink patterns not found: {config_path}")
        with open(config_path) as f:
            _SINKS_CONFIG = yaml.safe_load(f)
    return _SINKS_CONFIG


def classify_symbol(symbol: SymbolInfo, language: str) -> None:
    """Mutate symbol in place: set is_sink, is_entry_point, cwe_tags.

    Matches the symbol's qualified_name against sink patterns from sinks.yaml.
    Matches decorators against entry-point patterns.
    """
    config = _load_sinks_config()
    lang_config = config.get(language, {})

    # Sink classification
    for cwe_id, patterns in lang_config.get("sinks", {}).items():
        for pattern in patterns:
            if fnmatch(symbol.qualified_name, pattern) or \
               fnmatch(symbol.name, pattern.split(".")[-1]):
                symbol.is_sink = True
                if cwe_id not in symbol.cwe_tags:
                    symbol.cwe_tags.append(cwe_id)

    # Entry-point classification
    ep_config = lang_config.get("entry_points", {})
    if isinstance(ep_config, list):
        # Python: list of decorator patterns
        for dec in symbol.decorators:
            for pattern in ep_config:
                if fnmatch(dec, pattern):
                    symbol.is_entry_point = True
                    break
    elif isinstance(ep_config, dict):
        # C#: decorators + base_classes
        decorator_patterns = ep_config.get("decorators", [])
        base_patterns = ep_config.get("base_classes", [])
        for dec in symbol.decorators:
            if dec in decorator_patterns:
                symbol.is_entry_point = True
                break
        for base in symbol.bases:
            if base in base_patterns or any(base.endswith(f".{bp}") for bp in base_patterns):
                symbol.is_entry_point = True
                break
```

**Integration point:** Call `classify_symbol()` during parsing — in `parsers/python.py` after building each `SymbolInfo`, and in `parsers/csharp.py` after building each `SymbolInfo`. Alternatively, call it in `call_graph.py` after collecting all symbols — this is simpler and keeps parsers unchanged.

**Preferred approach:** Call in `call_graph.py` as a post-processing step over all collected `ModuleInfo` symbols. This keeps parsers pure (structural extraction only) and sinks.yaml is the single source of truth for security classification.

**Tests:** `tests/unit/test_code_analysis/test_sinks.py`
- Verify `execute` method matches CWE-89 sink
- Verify `HttpPost` decorator matches C# entry point
- Verify `@app.route` matches Python entry point
- Verify non-matching methods remain `is_sink=False`, `is_entry_point=False`
- Verify multiple CWE tags accumulate (a method can be both CWE-89 and CWE-78 sink)

### Task 0.5 — Combine call edges into unified CallGraph

**File:** `src/code_analysis/call_graph.py` (extend)

Add the top-level assembly function:

```python
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
    3. Classify sinks and entry points
    4. Build lookup indexes (file_symbols, symbol_files)
    """
    from code_analysis.graph import build_reference_graph
    from code_analysis.sinks import classify_symbol

    # 1. Get existing reference edges
    ref_graph = build_reference_graph(modules)

    # 2. Get call edges
    call_edges: list[CallEdge] = []
    if python_files:
        call_edges.extend(build_python_call_edges(root, python_files))
    if csharp_solution:
        call_edges.extend(build_csharp_call_edges(root, csharp_solution))

    # 3. Classify sinks and entry points
    for module in modules:
        lang = module.language
        for cls in module.classes:
            classify_symbol(cls, lang)
            for method in cls.methods:
                classify_symbol(method, lang)
        for func in module.functions:
            classify_symbol(func, lang)

    # 4. Build indexes
    all_symbols: list[str] = []
    file_symbols: dict[str, list[str]] = {}
    symbol_files: dict[str, str] = {}
    entry_points: list[str] = []
    sinks: dict[str, list[str]] = {}

    for module in modules:
        for cls in module.classes:
            _index_symbol(cls, module.path, all_symbols, file_symbols,
                          symbol_files, entry_points, sinks)
            for method in cls.methods:
                _index_symbol(method, module.path, all_symbols, file_symbols,
                              symbol_files, entry_points, sinks)
        for func in module.functions:
            _index_symbol(func, module.path, all_symbols, file_symbols,
                          symbol_files, entry_points, sinks)

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
```

**Tests:** `tests/unit/test_code_analysis/test_call_graph.py`
- Integration test with mock Python + C# modules
- Verify sinks are indexed by CWE
- Verify entry points are collected
- Verify file_symbols and symbol_files are correct

---

## Phase 1 — Graph-Powered File Selection (Week 1, Days 3-5)

### Task 1.1 — Graph walks (backward from sinks, forward from entry points)

**File:** `src/code_analysis/walk.py`

```python
"""Graph traversal for taint-aware file selection."""

from __future__ import annotations

from collections import deque

import structlog

from code_analysis.models import CallEdge, CallGraph

logger = structlog.get_logger()


def walk_backward_from_sinks(
    graph: CallGraph,
    cwe_id: str,
    max_hops: int = 5,
    min_confidence: float = 0.3,
) -> set[str]:
    """BFS backward from sinks tagged with cwe_id.

    Returns set of file_paths containing methods that can reach a sink
    within max_hops CALLS edges.

    Used for: CWE-89 (SQL injection), CWE-502 (deserialization),
    CWE-78 (command injection), CWE-22 (path traversal).
    """
    # Find seed nodes: sinks tagged with this CWE
    seed_nodes: set[str] = set()
    for qn, tags in graph.sinks.items():
        if cwe_id in tags:
            seed_nodes.add(qn)

    if not seed_nodes:
        return set()

    # Build reverse adjacency (callee → callers)
    reverse_adj: dict[str, list[str]] = {}
    for edge in graph.call_edges:
        if edge.confidence >= min_confidence:
            reverse_adj.setdefault(edge.callee, []).append(edge.caller)

    # BFS backward
    visited: set[str] = set(seed_nodes)
    frontier: deque[tuple[str, int]] = deque(
        (node, 0) for node in seed_nodes
    )
    reachable_files: set[str] = set()

    while frontier:
        node, depth = frontier.popleft()
        file_path = graph.symbol_files.get(node)
        if file_path:
            reachable_files.add(file_path)
        if depth < max_hops:
            for caller in reverse_adj.get(node, []):
                if caller not in visited:
                    visited.add(caller)
                    frontier.append((caller, depth + 1))

    logger.debug("walk.backward", cwe_id=cwe_id, sinks=len(seed_nodes),
                 reachable_files=len(reachable_files), max_depth=max_hops)
    return reachable_files


def walk_forward_from_entry_points(
    graph: CallGraph,
    max_hops: int = 3,
    min_confidence: float = 0.3,
    filter_decorators: list[str] | None = None,
) -> set[str]:
    """BFS forward from HTTP entry points.

    Returns set of file_paths reachable from entry points within max_hops.

    Used for: CWE-862 (missing authorization), CWE-863 (incorrect authorization).
    Optionally filter entry points by decorator (e.g. only POST/PUT/DELETE).
    """
    seed_nodes: set[str] = set()
    for qn in graph.entry_points:
        if filter_decorators is None:
            seed_nodes.add(qn)
        else:
            # Check if the symbol has any of the required decorators
            for file_path, symbols in graph.file_symbols.items():
                if qn in symbols:
                    seed_nodes.add(qn)
                    break

    if not seed_nodes:
        return set()

    # Build forward adjacency (caller → callees)
    forward_adj: dict[str, list[str]] = {}
    for edge in graph.call_edges:
        if edge.confidence >= min_confidence:
            forward_adj.setdefault(edge.caller, []).append(edge.callee)

    # BFS forward
    visited: set[str] = set(seed_nodes)
    frontier: deque[tuple[str, int]] = deque(
        (node, 0) for node in seed_nodes
    )
    reachable_files: set[str] = set()

    while frontier:
        node, depth = frontier.popleft()
        file_path = graph.symbol_files.get(node)
        if file_path:
            reachable_files.add(file_path)
        if depth < max_hops:
            for callee in forward_adj.get(node, []):
                if callee not in visited:
                    visited.add(callee)
                    frontier.append((callee, depth + 1))

    logger.debug("walk.forward", entry_points=len(seed_nodes),
                 reachable_files=len(reachable_files), max_depth=max_hops)
    return reachable_files


def walk_bidirectional(
    graph: CallGraph,
    cwe_id: str,
    max_hops: int = 4,
    min_confidence: float = 0.3,
) -> set[str]:
    """Walk both directions: backward from sinks AND forward from entry points.

    Returns the intersection (files on a path from entry point to sink).
    If either direction returns empty, falls back to the non-empty one.

    Used for: CWE-502 (deserialization from HTTP to sink).
    """
    backward = walk_backward_from_sinks(graph, cwe_id, max_hops, min_confidence)
    forward = walk_forward_from_entry_points(graph, max_hops, min_confidence)

    intersection = backward & forward
    if intersection:
        return intersection
    # Fallback: return backward (sinks are more specific)
    return backward if backward else forward
```

**Tests:** `tests/unit/test_code_analysis/test_walk.py`
- Build a fixture CallGraph with known chains: A→B→C→sink, D→E (no sink)
- Verify backward walk from CWE-89 sinks returns files for A, B, C but not D, E
- Verify max_hops=1 returns only C's file (direct caller of sink)
- Verify min_confidence filters low-confidence edges
- Verify forward walk from entry points returns reachable files
- Verify bidirectional returns intersection when both have results
- Verify empty sinks returns empty set (no crash)

### Task 1.2 — Extend CWE taxonomy with walk configuration

**File:** `config/taxonomy/cwe.yaml`

Add three new fields to each LLM-checked CWE. Existing fields are unchanged.

```yaml
"89":
  name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
  detection: sast+llm
  file_types: [model, repository, service, controller]
  walk_direction: backward      # NEW: backward from sinks
  max_hops: 5                   # NEW: BFS depth limit
  sink_patterns: [CWE-89]       # NEW: keys into sinks.yaml
  check: |
    Check for SQL queries built with string formatting or concatenation using user input.
    ...

"862":
  name: "Missing Authorization"
  detection: llm
  file_types: [controller, route, middleware]
  walk_direction: forward       # NEW: forward from entry points
  max_hops: 3
  check: |
    Check whether state-changing endpoints (POST, PUT, DELETE) have explicit
    authorization enforcement.
    ...

"502":
  name: "Deserialization of Untrusted Data"
  detection: sast+llm
  file_types: [api, service, message_handler]
  walk_direction: both          # NEW: bidirectional
  max_hops: 6
  sink_patterns: [CWE-502]
  check: |
    Trace data flow to deserialization sinks.
    ...
```

CWEs without `walk_direction` fall back to the existing keyword-based `file_types` matcher. This makes the migration incremental — you can add walk config to one CWE at a time.

**Update `CWECheck` dataclass** in `src/security_review/checks.py`:

```python
@dataclass(frozen=True)
class CWECheck:
    cwe_id: str
    name: str
    detection: str
    file_types: list[str]
    check_prompt: str
    walk_direction: str | None = None    # NEW: "backward", "forward", "both", or None
    max_hops: int = 5                    # NEW: BFS depth for graph walk
    sink_patterns: list[str] | None = None  # NEW: CWE keys into sinks.yaml
```

Update `load_cwe_checks()` to read the new fields:

```python
checks.append(CWECheck(
    cwe_id=str(cwe_id),
    name=entry.get("name", ""),
    detection=detection,
    file_types=entry.get("file_types", []),
    check_prompt=check_prompt.strip(),
    walk_direction=entry.get("walk_direction"),
    max_hops=entry.get("max_hops", 5),
    sink_patterns=entry.get("sink_patterns"),
))
```

### Task 1.3 — Replace file selector with graph-walk + keyword fallback

**File:** `src/security_review/checks.py`

Replace `select_files_for_check()` with a new function. Keep the old function as the fallback.

```python
def select_files_for_cwe(
    check: CWECheck,
    files: list[FileEntry],
    call_graph: CallGraph | None = None,
    pagerank: dict[str, float] | None = None,
) -> list[FileEntry]:
    """Select files relevant to a CWE check.

    Strategy (in order of preference):
    1. Graph walk (if call_graph is available and check has walk_direction)
    2. Keyword matching (existing logic, always available)
    3. High-security-weight fallback (security_weight >= 3)

    Results are sorted by PageRank score (descending) if available,
    so the most central files appear first in the token budget.
    """
    graph_files: set[str] | None = None

    # 1. Try graph walk
    if call_graph is not None and check.walk_direction:
        if check.walk_direction == "backward" and check.sink_patterns:
            for cwe_key in check.sink_patterns:
                result = walk_backward_from_sinks(
                    call_graph, cwe_key, check.max_hops)
                if graph_files is None:
                    graph_files = result
                else:
                    graph_files |= result
        elif check.walk_direction == "forward":
            graph_files = walk_forward_from_entry_points(
                call_graph, check.max_hops)
        elif check.walk_direction == "both" and check.sink_patterns:
            for cwe_key in check.sink_patterns:
                result = walk_bidirectional(
                    call_graph, cwe_key, check.max_hops)
                if graph_files is None:
                    graph_files = result
                else:
                    graph_files |= result

    # 2. Merge with keyword matches (union, not replace)
    keyword_files = _select_by_keywords(check, files)
    keyword_paths = {f.path for f in keyword_files}

    if graph_files:
        # Union of graph walk + keyword match
        all_paths = graph_files | keyword_paths
        selected = [f for f in files if f.path in all_paths
                    and f.language in ("python", "csharp")]
    elif keyword_files:
        selected = keyword_files
    else:
        # 3. Fallback: high security weight
        selected = [f for f in files
                    if f.language in ("python", "csharp")
                    and f.security_weight >= 3]

    # Sort by PageRank (highest first) for optimal token budget usage
    if pagerank and selected:
        def _file_rank(f: FileEntry) -> float:
            # Sum PageRank of all symbols in this file
            symbols = call_graph.file_symbols.get(f.path, []) if call_graph else []
            return sum(pagerank.get(s, 0.0) for s in symbols)
        selected.sort(key=_file_rank, reverse=True)

    logger.debug("select_files_for_cwe",
                 cwe=check.cwe_id,
                 graph_files=len(graph_files) if graph_files else 0,
                 keyword_files=len(keyword_paths),
                 total=len(selected),
                 method="graph" if graph_files else "keyword")
    return selected


def _select_by_keywords(
    check: CWECheck, files: list[FileEntry],
) -> list[FileEntry]:
    """Existing keyword-based file selection (preserved as fallback)."""
    if not check.file_types:
        return [f for f in files if f.language in ("python", "csharp")]

    keywords: set[str] = set()
    for ft in check.file_types:
        keywords.update(_FILE_TYPE_MATCHERS.get(ft, [ft]))

    matched = []
    for f in files:
        if f.language not in ("python", "csharp"):
            continue
        path_lower = f.path.lower()
        if any(kw in path_lower for kw in keywords):
            matched.append(f)
    return matched
```

**Key design decisions:**
- Graph walk and keyword match are **unioned**, not replaced. This prevents regressions — if the graph misses a file that keywords catch, it still gets included.
- Files are sorted by PageRank so the most central files consume the token budget first.
- `call_graph=None` is a valid input — the function gracefully degrades to keyword-only mode. This means no code changes are required in passes that haven't been updated yet.

**Tests:** `tests/unit/test_code_analysis/test_checks.py` (extend existing)
- Verify graph walk selects files not matched by keywords
- Verify keyword match still works when call_graph is None
- Verify union of graph + keyword results
- Verify PageRank sorting (highest-ranked file first)
- Verify fallback to security_weight >= 3 when both return empty

### Task 1.4 — PageRank on the call graph

**File:** `src/code_analysis/graph.py` (extend)

The existing `compute_pagerank()` works on `ReferenceGraph` (import/type edges only). Add a new function that computes PageRank on the full `CallGraph` (import + call edges combined).

```python
def compute_call_graph_pagerank(
    call_graph: CallGraph,
    damping: float = 0.85,
    max_iterations: int = 100,
    tolerance: float = 1e-6,
) -> dict[str, float]:
    """Compute PageRank on the combined call + reference graph.

    Returns normalized scores (0.0-1.0). Methods called by many other
    methods rank highest — these are the central utilities, shared services,
    and base classes that are most likely security-relevant.
    """
    # Build unified edge list
    all_edges: set[tuple[str, str]] = set()
    for edge in call_graph.call_edges:
        all_edges.add((edge.caller, edge.callee))
    for edge in call_graph.reference_edges:
        all_edges.add((edge.source, edge.target))

    # Reuse existing PageRank on a temporary ReferenceGraph
    temp_graph = ReferenceGraph(
        nodes=call_graph.nodes,
        edges=[ReferenceEdge(source=s, target=t) for s, t in all_edges],
    )
    return compute_pagerank(temp_graph, damping, max_iterations, tolerance)
```

### Task 1.5 — Wire into the holistic pass

**File:** `src/security_review/passes/holistic.py`

Modify `run_holistic()` to accept an optional `CallGraph` and `pagerank` dict, and pass them through to file selection.

The call graph is built **once** before Pass 4 starts (either in the pipeline orchestrator or at the start of `run_holistic`). It is not rebuilt per CWE check.

```python
async def run_holistic(
    state: PipelineState,
    call_graph: CallGraph | None = None,
    pagerank: dict[str, float] | None = None,
) -> None:
    # ... existing code ...

    # In the per-CWE-check loop, replace:
    #   files = select_files_for_check(check, state.manifest.files)
    # with:
    files = select_files_for_cwe(
        check, state.manifest.files,
        call_graph=call_graph,
        pagerank=pagerank,
    )
```

**File:** `src/security_review/passes/pipeline.py`

Build the call graph between Pass 1 and Pass 4:

```python
async def run_pipeline(state: PipelineState) -> None:
    await run_inventory(state)       # Pass 1
    await run_sast(state)            # Pass 2
    await run_triage(state)          # Pass 3

    # Build call graph (optional — degrades gracefully)
    call_graph, pagerank = _build_call_graph_if_available(state)

    await run_holistic(state, call_graph=call_graph, pagerank=pagerank)  # Pass 4
    await run_config_review(state)   # Pass 5
    await run_merge(state)           # Merge


def _build_call_graph_if_available(
    state: PipelineState,
) -> tuple[CallGraph | None, dict[str, float] | None]:
    """Build call graph from parsed modules. Returns (None, None) if not available."""
    try:
        from code_analysis.call_graph import build_call_graph
        from code_analysis.graph import compute_call_graph_pagerank

        # Collect modules from Pass 1 manifest (if structural analysis was done)
        modules = state.modules if hasattr(state, 'modules') and state.modules else []
        if not modules:
            return None, None

        python_files = [
            state.target_path / f.path
            for f in state.manifest.files
            if f.language == "python"
        ]
        # Find .sln or .csproj for C#
        csharp_solution = _find_csharp_project(state.target_path)

        graph = build_call_graph(
            state.target_path, modules,
            python_files=python_files,
            csharp_solution=csharp_solution,
        )
        pagerank = compute_call_graph_pagerank(graph)
        logger.info("pipeline.call_graph_built",
                     nodes=len(graph.nodes),
                     call_edges=len(graph.call_edges),
                     entry_points=len(graph.entry_points),
                     sinks=sum(len(v) for v in graph.sinks.values()))
        return graph, pagerank
    except Exception as e:
        logger.warning("pipeline.call_graph_failed", error=str(e))
        return None, None
```

**Important:** The pipeline must store `modules` (list of `ModuleInfo`) from Pass 1 into `PipelineState`. Currently, Pass 1 produces `FileManifest` but may not store structural data. Check whether `run_inventory()` already does structural parsing — if not, add it.

Add to `PipelineState` in `src/security_review/passes/state.py`:

```python
@dataclass
class PipelineState:
    # ... existing fields ...
    modules: list[ModuleInfo] | None = None  # NEW: structural data for call graph
```

Populate `state.modules` in Pass 1 when structural analysis is available.

---

## Phase 2 — SQLite Persistence (Week 2, Days 1-3)

### Task 2.1 — SQLite store

**File:** `src/code_analysis/store.py`

```python
"""SQLite persistence for call graphs and findings."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import structlog

from code_analysis.models import CallEdge, CallGraph

logger = structlog.get_logger()

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS file_cache (
    file_path   TEXT PRIMARY KEY,
    sha256      TEXT NOT NULL,
    language    TEXT NOT NULL,
    parsed_at   TEXT NOT NULL DEFAULT (datetime('now')),
    symbol_count INTEGER NOT NULL DEFAULT 0,
    edge_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS symbols (
    qualified_name TEXT PRIMARY KEY,
    file_path      TEXT NOT NULL REFERENCES file_cache(file_path) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    line_number    INTEGER NOT NULL,
    end_line       INTEGER NOT NULL DEFAULT 0,
    is_entry_point INTEGER NOT NULL DEFAULT 0,
    is_sink        INTEGER NOT NULL DEFAULT 0,
    cwe_tags       TEXT NOT NULL DEFAULT '[]',
    decorators     TEXT NOT NULL DEFAULT '[]',
    visibility     TEXT NOT NULL DEFAULT 'public'
);
CREATE INDEX IF NOT EXISTS ix_symbols_file ON symbols(file_path);
CREATE INDEX IF NOT EXISTS ix_symbols_sink ON symbols(is_sink) WHERE is_sink = 1;
CREATE INDEX IF NOT EXISTS ix_symbols_entry ON symbols(is_entry_point) WHERE is_entry_point = 1;

CREATE TABLE IF NOT EXISTS call_edges (
    caller      TEXT NOT NULL,
    callee      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    line        INTEGER NOT NULL,
    confidence  REAL NOT NULL DEFAULT 0.5,
    kind        TEXT NOT NULL DEFAULT 'direct',
    PRIMARY KEY (caller, callee, line)
);
CREATE INDEX IF NOT EXISTS ix_edges_callee ON call_edges(callee);
CREATE INDEX IF NOT EXISTS ix_edges_caller ON call_edges(caller);

CREATE TABLE IF NOT EXISTS reference_edges (
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    PRIMARY KEY (source, target)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    repo_root   TEXT NOT NULL,
    git_sha     TEXT,
    scar_version TEXT NOT NULL,
    config_hash TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT NOT NULL,
    run_id      TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    cwe_id      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    symbol      TEXT,
    message     TEXT NOT NULL,
    confidence  REAL NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    first_seen_run TEXT,
    last_seen_run  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (fingerprint, run_id)
);
CREATE INDEX IF NOT EXISTS ix_findings_cwe ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS ix_findings_file ON findings(file_path);
"""


class GraphStore:
    """SQLite-backed persistent store for call graphs and findings."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._ensure_version()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _ensure_version(self) -> None:
        row = self._conn.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_version(version) VALUES(?)",
                (SCHEMA_VERSION,))
            self._conn.commit()

    def file_needs_reindex(self, file_path: str, sha256: str) -> bool:
        """Check if a file needs re-parsing (content changed or not cached)."""
        row = self._conn.execute(
            "SELECT sha256 FROM file_cache WHERE file_path=?",
            (file_path,)).fetchone()
        return row is None or row[0] != sha256

    def delete_file_data(self, file_path: str) -> None:
        """Remove all symbols and edges for a file (CASCADE from file_cache)."""
        self._conn.execute("DELETE FROM symbols WHERE file_path=?", (file_path,))
        self._conn.execute("DELETE FROM call_edges WHERE file_path=?", (file_path,))
        self._conn.execute("DELETE FROM file_cache WHERE file_path=?", (file_path,))

    def upsert_file(self, file_path: str, sha256: str, language: str,
                     symbol_count: int, edge_count: int) -> None:
        self._conn.execute("""
            INSERT INTO file_cache(file_path, sha256, language, symbol_count, edge_count)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                sha256=excluded.sha256, parsed_at=datetime('now'),
                symbol_count=excluded.symbol_count, edge_count=excluded.edge_count
        """, (file_path, sha256, language, symbol_count, edge_count))

    def insert_symbols(self, symbols: list[dict]) -> None:
        self._conn.executemany("""
            INSERT OR REPLACE INTO symbols(
                qualified_name, file_path, kind, line_number, end_line,
                is_entry_point, is_sink, cwe_tags, decorators, visibility
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [(
            s["qualified_name"], s["file_path"], s["kind"],
            s["line_number"], s.get("end_line", 0),
            int(s.get("is_entry_point", False)),
            int(s.get("is_sink", False)),
            json.dumps(s.get("cwe_tags", [])),
            json.dumps(s.get("decorators", [])),
            s.get("visibility", "public"),
        ) for s in symbols])

    def insert_call_edges(self, edges: list[CallEdge]) -> None:
        self._conn.executemany("""
            INSERT OR REPLACE INTO call_edges(caller, callee, file_path, line, confidence, kind)
            VALUES(?, ?, ?, ?, ?, ?)
        """, [(e.caller, e.callee, e.file_path, e.line, e.confidence, e.kind)
              for e in edges])

    def commit(self) -> None:
        self._conn.commit()

    def load_call_graph(self) -> CallGraph:
        """Reconstruct a CallGraph from the persisted data."""
        symbols = self._conn.execute(
            "SELECT qualified_name, file_path, is_entry_point, is_sink, cwe_tags "
            "FROM symbols").fetchall()

        nodes = []
        entry_points = []
        sinks: dict[str, list[str]] = {}
        file_symbols: dict[str, list[str]] = {}
        symbol_files: dict[str, str] = {}

        for qn, fp, is_ep, is_s, cwe_json in symbols:
            nodes.append(qn)
            symbol_files[qn] = fp
            file_symbols.setdefault(fp, []).append(qn)
            if is_ep:
                entry_points.append(qn)
            if is_s:
                sinks[qn] = json.loads(cwe_json)

        call_rows = self._conn.execute(
            "SELECT caller, callee, file_path, line, confidence, kind "
            "FROM call_edges").fetchall()
        call_edges = [
            CallEdge(caller=r[0], callee=r[1], file_path=r[2],
                     line=r[3], confidence=r[4], kind=r[5])
            for r in call_rows
        ]

        ref_rows = self._conn.execute(
            "SELECT source, target FROM reference_edges").fetchall()
        from code_analysis.models import ReferenceEdge
        ref_edges = [ReferenceEdge(source=r[0], target=r[1]) for r in ref_rows]

        return CallGraph(
            nodes=sorted(set(nodes)),
            call_edges=call_edges,
            reference_edges=ref_edges,
            entry_points=entry_points,
            sinks=sinks,
            file_symbols=file_symbols,
            symbol_files=symbol_files,
        )

    def get_changed_files(self, file_shas: dict[str, str]) -> list[str]:
        """Return files that need re-indexing (new, modified, or deleted)."""
        changed = []
        for file_path, sha in file_shas.items():
            if self.file_needs_reindex(file_path, sha):
                changed.append(file_path)
        # Also detect deleted files (in cache but not in file_shas)
        cached = {row[0] for row in
                  self._conn.execute("SELECT file_path FROM file_cache").fetchall()}
        deleted = cached - set(file_shas.keys())
        for fp in deleted:
            self.delete_file_data(fp)
        self.commit()
        return changed
```

**Location of the database:** `.scar/graph.db` inside the target repository root. This keeps it alongside the codebase and gets `.gitignore`d.

**Superseded by plan 021 WP-D:** the cache now lives in SCAR's own `var/cache/graphs/<target-key>/`; SCAR no longer writes into the scanned repository.

Add to the target repo's `.gitignore` (or create `.scar/.gitignore`):
```
.scar/
```

**Tests:** `tests/unit/test_code_analysis/test_store.py`
- Use `tmp_path` fixture for SQLite DB
- Verify round-trip: insert symbols + edges, commit, load_call_graph, verify equality
- Verify incremental: file_needs_reindex returns True for new SHA, False for same SHA
- Verify delete_file_data cascades
- Verify get_changed_files detects new, modified, and deleted files

### Task 2.2 — Incremental reindexing

**File:** `src/code_analysis/call_graph.py` (extend)

Add an incremental build function:

```python
def build_call_graph_incremental(
    root: Path,
    modules: list[ModuleInfo],
    store: GraphStore,
    *,
    python_files: list[Path] | None = None,
    csharp_solution: Path | None = None,
) -> CallGraph:
    """Build call graph, reusing cached data for unchanged files.

    1. Compute SHA256 for each source file
    2. Ask store which files changed
    3. Re-parse only changed files
    4. Update store with new symbols and edges
    5. Load full graph from store
    """
    # 1. Compute SHAs
    file_shas: dict[str, str] = {}
    for module in modules:
        full_path = root / module.path
        if full_path.exists():
            content = full_path.read_bytes()
            file_shas[module.path] = hashlib.sha256(content).hexdigest()

    # 2. Find changed files
    changed = store.get_changed_files(file_shas)

    if not changed:
        logger.info("call_graph.incremental", changed=0, cached="all")
        return store.load_call_graph()

    logger.info("call_graph.incremental",
                changed=len(changed), total=len(file_shas))

    # 3. Re-parse changed files only
    changed_modules = [m for m in modules if m.path in changed]

    # Get call edges for changed Python files
    changed_py = [root / m.path for m in changed_modules if m.language == "python"]
    py_edges = build_python_call_edges(root, changed_py) if changed_py else []

    # C# edges: re-extract all (Roslyn needs full solution context)
    cs_edges: list[CallEdge] = []
    if csharp_solution and any(m.language == "csharp" for m in changed_modules):
        cs_edges = build_csharp_call_edges(root, csharp_solution)

    # 4. Update store
    from code_analysis.sinks import classify_symbol

    for module in changed_modules:
        store.delete_file_data(module.path)

        # Classify symbols
        for cls in module.classes:
            classify_symbol(cls, module.language)
            for method in cls.methods:
                classify_symbol(method, module.language)
        for func in module.functions:
            classify_symbol(func, module.language)

        # Insert symbols
        symbols_data = _module_to_symbol_dicts(module)
        store.insert_symbols(symbols_data)

        # Insert edges from this file
        file_edges = [e for e in py_edges + cs_edges if e.file_path == module.path]
        store.insert_call_edges(file_edges)

        store.upsert_file(
            module.path,
            file_shas[module.path],
            module.language,
            len(symbols_data),
            len(file_edges),
        )

    store.commit()

    # 5. Load full graph
    return store.load_call_graph()
```

### Task 2.3 — Finding fingerprinting and cross-run tracking

**File:** `src/security_review/fingerprint.py`

```python
"""Stable finding fingerprints for cross-run deduplication."""

from __future__ import annotations

import hashlib
import re


def fingerprint_finding(
    cwe_id: str,
    qualified_name: str,
    file_path: str,
    code_snippet: str,
) -> str:
    """Compute a stable fingerprint for a finding.

    Stable across whitespace and comment changes.
    Breaks on structural code changes (which is correct — the finding
    may have been fixed or changed).
    """
    # Normalize whitespace
    s = re.sub(r'\s+', ' ', code_snippet.strip())
    # Strip single-line comments
    s = re.sub(r'#.*$', '', s, flags=re.MULTILINE)
    s = re.sub(r'//.*$', '', s, flags=re.MULTILINE)

    raw = f"{cwe_id}|{qualified_name}|{file_path}|{s}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

Wire into the merge pass: after computing findings, fingerprint each one and upsert into the `findings` table via `GraphStore`. On each run, compare fingerprints to detect:
- **New findings** (fingerprint not in previous runs)
- **Recurring findings** (fingerprint matches a previous run — update `last_seen_run`)
- **Resolved findings** (fingerprint in previous run but not in current — keep in DB with status)

**Tests:** `tests/unit/test_fingerprint.py`
- Verify same code with different whitespace produces same fingerprint
- Verify same code with different comments produces same fingerprint
- Verify structurally different code produces different fingerprint
- Verify all components (cwe_id, qualified_name, file_path) affect the fingerprint

---

## Phase 3 — Measurement and Tuning (Week 2, Days 3-5)

### Task 3.1 — File selection telemetry

Add structured logging to `select_files_for_cwe()` that records, per CWE check:
- `method`: "graph", "keyword", "fallback"
- `graph_files_count`: files from graph walk
- `keyword_files_count`: files from keyword match
- `total_files_selected`: final count
- `files_with_findings`: files where the LLM actually found something (set after the LLM call)

This data is written to `triage.json` alongside existing audit trail data.

### Task 3.2 — Diff-aware CWE check selection

When the graph store has data from a previous run and the target repo has a git diff:

```python
def select_cwe_checks_for_diff(
    all_checks: list[CWECheck],
    changed_files: list[str],
    call_graph: CallGraph,
    max_hops: int = 2,
) -> list[CWECheck]:
    """Select only CWE checks affected by changed files.

    A CWE check is affected if any of the changed files (or files within
    max_hops of them in the call graph) contain sinks or entry points
    relevant to that CWE.

    Returns the full check list if call_graph has no data or all files changed.
    """
    if not changed_files or not call_graph.call_edges:
        return all_checks

    # Find blast radius: changed files + N-hop neighbors
    blast_files = set(changed_files)
    # ... BFS from changed files along call edges in both directions ...

    # Filter checks: keep checks where any blast-radius file contains
    # a relevant sink or entry point
    affected: list[CWECheck] = []
    for check in all_checks:
        if _check_affects_files(check, blast_files, call_graph):
            affected.append(check)

    if not affected:
        return all_checks  # safety: don't skip everything

    return affected
```

This is an **optimization** — it reduces LLM calls on incremental reviews. It does not change correctness (worst case: all checks run, same as today).

### Task 3.3 — A/B comparison: graph vs keyword file selection

Add a `--compare-selection` flag to `scar.py test-cwe` that runs both selection methods and reports:
- Files selected by graph only (keyword missed)
- Files selected by keyword only (graph missed)
- Files selected by both
- Which selection found the actual findings

This produces the dataset needed to measure whether graph selection is actually better.

---

## Dependency Changes

**`pyproject.toml` additions:**

```toml
[project]
dependencies = [
    # ... existing ...
    "rustworkx>=0.15",     # Fast graph algorithms (PageRank, BFS, community detection)
]

[project.optional-dependencies]
callgraph = [
    "pyan3>=2.6",          # Python call graph extraction
]
```

**`requirements.txt` additions:**

```
rustworkx>=0.15        # Graph algorithms (replaces hand-rolled PageRank)
pyan3>=2.6             # Python call graph (optional, degrades gracefully)
```

pyan3 is optional because it requires the target codebase to be parseable Python. rustworkx is required because it replaces the hand-rolled PageRank with a battle-tested implementation that also provides BFS, Louvain community detection, and shortest-path algorithms.

The Roslyn callgraph tool is a separate .NET project — it is NOT a Python dependency. It is built with `dotnet build tools/roslyn-callgraph/` and invoked via subprocess through `tools/runner.py`.

---

## Files Created (New)

| File | Purpose |
|---|---|
| `src/code_analysis/call_graph.py` | Call graph builder (pyan3 + Roslyn integration) |
| `src/code_analysis/sinks.py` | Sink/entry-point classification |
| `src/code_analysis/walk.py` | BFS graph walks (backward/forward/bidirectional) |
| `src/code_analysis/store.py` | SQLite persistence for graph + findings |
| `src/security_review/fingerprint.py` | Finding fingerprinting |
| `config/taxonomy/sinks.yaml` | Sink/entry-point patterns per language per CWE |
| `tools/roslyn-callgraph/roslyn-callgraph.csproj` | .NET 8 Roslyn tool project |
| `tools/roslyn-callgraph/Program.cs` | Roslyn call graph extractor |
| `tests/unit/test_code_analysis/test_call_graph.py` | Call graph tests |
| `tests/unit/test_code_analysis/test_sinks.py` | Sink classification tests |
| `tests/unit/test_code_analysis/test_walk.py` | Graph walk tests |
| `tests/unit/test_code_analysis/test_store.py` | SQLite store tests |
| `tests/unit/test_fingerprint.py` | Fingerprint tests |

## Files Modified

| File | Changes |
|---|---|
| `src/code_analysis/models.py` | Add `CallEdge`, `CallGraph`; extend `SymbolInfo` with `is_entry_point`, `is_sink`, `cwe_tags` |
| `src/code_analysis/graph.py` | Add `compute_call_graph_pagerank()` |
| `src/security_review/checks.py` | Add `select_files_for_cwe()`; keep `select_files_for_check()` as `_select_by_keywords()` |
| `src/security_review/passes/holistic.py` | Pass `call_graph` and `pagerank` to file selection |
| `src/security_review/passes/pipeline.py` | Build call graph between Pass 1 and Pass 4 |
| `src/security_review/passes/state.py` | Add `modules: list[ModuleInfo] \| None` to `PipelineState` |
| `config/taxonomy/cwe.yaml` | Add `walk_direction`, `max_hops`, `sink_patterns` to LLM-checked CWEs |
| `pyproject.toml` | Add `rustworkx`, optional `pyan3` |
| `requirements.txt` | Add `rustworkx`, `pyan3` |

---

## Testing Strategy

### Unit tests (no external tools, no LLM calls)

All new modules have unit tests with fixture data. No real codebases needed.

```bash
pytest tests/unit/test_code_analysis/test_call_graph.py -v
pytest tests/unit/test_code_analysis/test_sinks.py -v
pytest tests/unit/test_code_analysis/test_walk.py -v
pytest tests/unit/test_code_analysis/test_store.py -v
pytest tests/unit/test_fingerprint.py -v
```

### Integration test (real codebase, no LLM)

Run call graph extraction on the `eval/` corpus and a real target repo:

```bash
pytest tests/integration/test_call_graph_integration.py -v
```

Verify:
- pyan3 extracts edges from Python eval fixtures
- Roslyn tool extracts edges from C# eval fixtures (if .NET SDK available)
- Graph walks from known sinks return expected files
- SQLite round-trip preserves all data

### Regression test (real LLM calls)

Use existing `tests/regression/` framework to verify that graph-based file selection does not degrade detection:

```bash
pytest tests/regression/ -v --provider claude:claude-opus
```

Compare results against golden baseline. Any CWE that previously passed but now fails indicates a file selection regression.

---

## Go/No-Go Criteria

### Phase 0 → Phase 1

- pyan3 extracts ≥100 call edges from a real 500-file Python codebase
- OR Roslyn tool extracts ≥100 call edges from a real C# solution
- All unit tests pass
- No existing unit tests broken

### Phase 1 → Phase 2

- Graph-walk file selection selects ≥1 file that keyword matching misses, for at least 3 of the 11 baseline CWEs
- No regression tests fail (golden baseline unchanged or improved)
- PageRank-sorted file ordering does not degrade LLM detection rates

### Phase 2 → Phase 3

- SQLite incremental reindex of 5 changed files completes in <5 seconds
- Full cold reindex of 500 files completes in <60 seconds
- `scar.py review` startup time remains under 3 seconds (including SQLite open + graph load)

---

## Risks

| Risk | Mitigation |
|---|---|
| pyan3 API differs from documented | Read pyan3 v2.6 source before implementing; fall back to tree-sitter heuristic call edges |
| pyan3 fails on large/complex codebases | Timeout per-file (30s), skip failures, log warnings, degrade to keyword selection |
| Roslyn tool requires .NET SDK not installed | Tool is optional; if not available, C# gets keyword-only selection (same as today) |
| Call graph has >30% false edges | Acceptable per research — 2.2x file inflation, LLM filters noise. Log and measure. |
| SQLite adds startup overhead | WAL mode, single file, no connection pool needed. Benchmark shows <50ms for 50k rows. |
| Graph walk returns too many files for token budget | Token budget in `context_builder.py` already truncates. PageRank sorting ensures best files are included first. |
| Subprocess isolation violated by Roslyn tool | Route through `tools/runner.py` — add sync variant |

---

## What This Plan Does NOT Include

1. **PostgreSQL, Apache AGE, or any external database.** SQLite only.
2. **pgvector or code embeddings.** Skip until measurements prove keyword + graph misses >15% of relevant files.
3. **Community detection (Louvain).** Listed in research as a "nice to have" but deferred — PageRank + BFS walks cover the primary use case. Add later if file clustering becomes a measured need.
4. **Changes to LLM agents, prompts, or output parsing.** The LLM layer is unchanged. Only file selection is affected.
5. **Changes to SAST tools or Pass 2.** Deterministic tools are unaffected.
6. **Multi-process concurrency.** SQLite WAL mode supports concurrent reads, but SCAR remains single-process.
