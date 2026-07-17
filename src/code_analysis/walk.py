"""Graph traversal for taint-aware file selection.

Seed detection for the backward walk matches sink patterns two ways: against
call_edges' own callee names directly (matches_any_sink_pattern), and against
graph.sinks (locally-defined symbols pre-classified by classify_symbol()).
The direct match is the primary mechanism -- real-world sinks (cursor.execute,
os.system, pickle.loads) are external library calls that never appear as a
locally-defined symbol, so graph.sinks alone would rarely find anything.
"""

from __future__ import annotations

from collections import deque

import structlog

from code_analysis.models import CallGraph
from code_analysis.sinks import matches_any_sink_pattern

logger = structlog.get_logger()


def _seed_nodes_for_sink(graph: CallGraph, cwe_id: str) -> set[str]:
    seeds: set[str] = {qn for qn, tags in graph.sinks.items() if cwe_id in tags}
    for edge in graph.call_edges:
        if matches_any_sink_pattern(edge.callee, cwe_id):
            seeds.add(edge.caller)
    return seeds


def walk_backward_from_sinks(
    graph: CallGraph,
    cwe_id: str,
    max_hops: int = 5,
    min_confidence: float = 0.3,
) -> set[str]:
    """BFS backward from sinks tagged with cwe_id.

    Returns the set of file_paths containing methods that can reach a sink
    within max_hops CALLS edges.

    Used for: CWE-89 (SQL injection), CWE-502 (deserialization),
    CWE-78 (command injection), CWE-22 (path traversal).
    """
    seed_nodes = _seed_nodes_for_sink(graph, cwe_id)
    if not seed_nodes:
        return set()

    reverse_adj: dict[str, list[str]] = {}
    for edge in graph.call_edges:
        if edge.confidence >= min_confidence:
            reverse_adj.setdefault(edge.callee, []).append(edge.caller)

    visited: set[str] = set(seed_nodes)
    frontier: deque[tuple[str, int]] = deque((node, 0) for node in seed_nodes)
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
                 reachable_files=len(reachable_files), max_hops=max_hops)
    return reachable_files


def walk_forward_from_entry_points(
    graph: CallGraph,
    max_hops: int = 3,
    min_confidence: float = 0.3,
) -> set[str]:
    """BFS forward from HTTP entry points.

    Returns the set of file_paths reachable from entry points within max_hops.

    Used for: CWE-862 (missing authorization), CWE-863 (incorrect authorization).
    """
    seed_nodes: set[str] = set(graph.entry_points)
    if not seed_nodes:
        return set()

    forward_adj: dict[str, list[str]] = {}
    for edge in graph.call_edges:
        if edge.confidence >= min_confidence:
            forward_adj.setdefault(edge.caller, []).append(edge.callee)

    visited: set[str] = set(seed_nodes)
    frontier: deque[tuple[str, int]] = deque((node, 0) for node in seed_nodes)
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
                 reachable_files=len(reachable_files), max_hops=max_hops)
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
    return backward if backward else forward
