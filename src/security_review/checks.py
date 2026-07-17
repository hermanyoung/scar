"""CWE check registry — loads LLM security checks from taxonomy/cwe.yaml.

The taxonomy is the single source of truth. Each CWE declares its detection
method (sast, llm, sast+llm, tool) and, for LLM-checked CWEs, a focused
check prompt. This module loads and filters those checks for Pass 4.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import structlog
import yaml

from security_review import MODULE_ROOT
from security_review.errors import ConfigurationError
from security_review.models.inventory import FileEntry

from code_analysis.models import CallGraph
from code_analysis.sinks import matches_any_sink_pattern
from code_analysis.walk import walk_backward_from_sinks, walk_bidirectional, walk_forward_from_entry_points

logger = structlog.get_logger()


@dataclass(frozen=True)
class FileSelectionTelemetry:
    """Records how select_files_for_cwe() chose files for one CWE check.

    Written to triage.json alongside the audit trail (Phase 3 measurement --
    lets a later run compare graph-walk selection against keyword selection
    without needing --compare-selection's live A/B pass).
    """

    cwe_id: str
    method: str  # "graph" or "keyword"
    graph_files_count: int
    keyword_files_count: int
    total_files_selected: int


@dataclass(frozen=True)
class CWECheck:
    """A single CWE check to be executed by the LLM agent."""

    cwe_id: str
    name: str
    detection: str
    file_types: list[str]
    check_prompt: str
    walk_direction: str | None = None       # "backward", "forward", "both", or None
    max_hops: int = 5                       # BFS depth for walk_direction
    sink_patterns: list[str] | None = None  # CWE keys into config/taxonomy/sinks.yaml

    @property
    def display_name(self) -> str:
        return f"CWE-{self.cwe_id} {self.name}"

    @property
    def short_name(self) -> str:
        """Short display for progress: 'CWE-862 Missing Authorization'."""
        name = self.name
        # Truncate long CWE names at the parenthetical
        if "(" in name:
            name = name[:name.index("(")].strip()
        if len(name) > 50:
            name = name[:47] + "..."
        return f"CWE-{self.cwe_id} {name}"


def load_cwe_checks() -> list[CWECheck]:
    """Load all CWE checks that require LLM reasoning from the taxonomy.

    Returns checks where detection is 'llm' or 'sast+llm' and a check
    prompt is defined.
    """
    cwe_path = MODULE_ROOT / "config" / "taxonomy" / "cwe.yaml"
    if not cwe_path.exists():
        raise ConfigurationError(
            f"CWE taxonomy not found: {cwe_path}",
            code="SYS_CWE_NOT_FOUND",
        )

    with open(cwe_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"CWE taxonomy is not a YAML mapping: {cwe_path}",
            code="SYS_CWE_NOT_FOUND",
        )

    checks: list[CWECheck] = []
    for cwe_id, entry in data.items():
        if not isinstance(entry, dict):
            continue

        detection = entry.get("detection", "sast")
        check_prompt = entry.get("check")

        if detection in ("llm", "sast+llm") and check_prompt:
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

    return checks


# File type keywords matched against FileEntry fields
_FILE_TYPE_MATCHERS: dict[str, list[str]] = {
    "controller": ["controller", "views", "endpoints", "api", "routes"],
    "route": ["routes", "urls", "router", "endpoints"],
    "view": ["views", "templates", "pages"],
    "template": ["templates", "views", "pages", "razor", "jinja"],
    "model": ["models", "entities", "domain"],
    "repository": ["repositories", "dal", "data"],
    "service": ["services", "handlers", "managers", "processors"],
    "middleware": ["middleware", "filters", "interceptors"],
    "auth": ["auth", "identity", "login", "oauth", "jwt", "token", "bearer", "claims"],
    "config": ["config", "settings", "appsettings", "startup", "program"],
    "startup": ["startup", "program", "main", "app", "host"],
    "error_handler": ["error", "exception", "handler", "middleware"],
    "file_handler": ["file", "upload", "download", "storage", "blob"],
    "crypto": ["crypto", "cipher", "encrypt", "hash", "key", "cert", "ssl", "tls"],
    "api": ["api", "controller", "endpoints", "routes", "views"],
    "message_handler": ["consumer", "handler", "processor", "worker", "listener"],
    "dockerfile": ["dockerfile", "docker-compose", "containerfile"],
}


def select_files_for_check(
    check: CWECheck,
    files: list[FileEntry],
) -> list[FileEntry]:
    """Select files relevant to a CWE check based on file_types.

    Matches file paths against keywords associated with each file_type.
    Falls back to all source files if no file_types specified or no matches found.
    """
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

    # If keyword matching found nothing, fall back to high-security-weight
    # files only — not the entire codebase. Prevents budget exhaustion on
    # large repos when file_types keywords don't match directory names.
    if not matched:
        high_weight = [
            f for f in files
            if f.language in ("python", "csharp") and f.security_weight >= 3
        ]
        logger.debug(
            "checks.keyword_match_fallback",
            cwe_id=check.cwe_id,
            file_types=check.file_types,
            keywords=sorted(keywords),
            high_weight_files=len(high_weight),
        )
        return high_weight if high_weight else []

    return matched


def select_files_for_cwe(
    check: CWECheck,
    files: list[FileEntry],
    call_graph: CallGraph | None = None,
    pagerank: dict[str, float] | None = None,
) -> tuple[list[FileEntry], FileSelectionTelemetry]:
    """Select files relevant to a CWE check, adding call-graph reach on top.

    Strategy:
    1. Graph walk (if call_graph is available and check.walk_direction is set)
    2. select_files_for_check() -- keyword matching, with its own
       high-security-weight fallback when no keywords match. Always run,
       and always unioned with (1) rather than replaced by it, so a graph
       miss never regresses what keyword matching already found.

    Results are sorted by summed PageRank of each file's symbols (descending)
    when pagerank is available, so the most central files consume the token
    budget first.

    call_graph=None is a valid input -- degrades to keyword-only selection,
    identical to calling select_files_for_check() directly.
    """
    graph_files: set[str] | None = None

    if call_graph is not None and check.walk_direction:
        if check.walk_direction == "backward" and check.sink_patterns:
            graph_files = set()
            for cwe_key in check.sink_patterns:
                graph_files |= walk_backward_from_sinks(call_graph, cwe_key, check.max_hops)
        elif check.walk_direction == "forward":
            graph_files = walk_forward_from_entry_points(call_graph, check.max_hops)
        elif check.walk_direction == "both" and check.sink_patterns:
            graph_files = set()
            for cwe_key in check.sink_patterns:
                graph_files |= walk_bidirectional(call_graph, cwe_key, check.max_hops)

    keyword_selected = select_files_for_check(check, files)

    if graph_files:
        keyword_paths = {f.path for f in keyword_selected}
        all_paths = graph_files | keyword_paths
        selected = [f for f in files if f.path in all_paths and f.language in ("python", "csharp")]
    else:
        selected = keyword_selected

    if pagerank and call_graph and selected:
        def _file_rank(f: FileEntry) -> float:
            symbols = call_graph.file_symbols.get(f.path, [])
            return sum(pagerank.get(s, 0.0) for s in symbols)
        selected.sort(key=_file_rank, reverse=True)

    telemetry = FileSelectionTelemetry(
        cwe_id=check.cwe_id,
        method="graph" if graph_files else "keyword",
        graph_files_count=len(graph_files) if graph_files else 0,
        keyword_files_count=len(keyword_selected),
        total_files_selected=len(selected),
    )
    logger.debug("checks.select_files_for_cwe", **telemetry.__dict__)
    return selected, telemetry


def _blast_radius_files(call_graph: CallGraph, changed_files: list[str], max_hops: int) -> set[str]:
    """Changed files plus their N-hop neighbors in the call graph, both directions."""
    seed_symbols: set[str] = set()
    for changed in changed_files:
        seed_symbols.update(call_graph.file_symbols.get(changed, []))

    adjacency: dict[str, list[str]] = {}
    for edge in call_graph.call_edges:
        adjacency.setdefault(edge.caller, []).append(edge.callee)
        adjacency.setdefault(edge.callee, []).append(edge.caller)

    visited: set[str] = set(seed_symbols)
    frontier: deque[tuple[str, int]] = deque((s, 0) for s in seed_symbols)
    blast_files: set[str] = set(changed_files)

    while frontier:
        node, depth = frontier.popleft()
        file_path = call_graph.symbol_files.get(node)
        if file_path:
            blast_files.add(file_path)
        if depth < max_hops:
            for neighbor in adjacency.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    frontier.append((neighbor, depth + 1))

    return blast_files


def _check_affects_files(check: CWECheck, blast_files: set[str], call_graph: CallGraph) -> bool:
    """Would this CWE check plausibly find something different in the blast radius?"""
    if check.walk_direction == "forward":
        return any(call_graph.symbol_files.get(ep) in blast_files for ep in call_graph.entry_points)

    if check.walk_direction in ("backward", "both") and check.sink_patterns:
        for edge in call_graph.call_edges:
            if edge.file_path in blast_files and any(
                matches_any_sink_pattern(edge.callee, cwe_key) for cwe_key in check.sink_patterns
            ):
                return True
        return False

    # Keyword-only check: affected if any blast-radius file matches its file_types.
    if not check.file_types:
        return True
    keywords: set[str] = set()
    for ft in check.file_types:
        keywords.update(_FILE_TYPE_MATCHERS.get(ft, [ft]))
    return any(any(kw in f.lower() for kw in keywords) for f in blast_files)


def select_cwe_checks_for_diff(
    all_checks: list[CWECheck],
    changed_files: list[str],
    call_graph: CallGraph,
    max_hops: int = 2,
) -> list[CWECheck]:
    """Select only CWE checks plausibly affected by changed_files.

    This is an optimization for incremental reviews (fewer LLM calls), never
    a correctness change: worst case it returns every check, same as today.
    Returns all_checks when there's nothing to narrow from (no changed files,
    no call graph data, or narrowing would eliminate every check).
    """
    if not changed_files or not call_graph.call_edges:
        return all_checks

    blast_files = _blast_radius_files(call_graph, changed_files, max_hops)

    affected = [c for c in all_checks if _check_affects_files(c, blast_files, call_graph)]

    return affected if affected else all_checks
