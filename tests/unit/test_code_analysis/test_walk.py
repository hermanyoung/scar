"""Tests for graph-walk-based file selection."""

from __future__ import annotations

from code_analysis.models import CallEdge, CallGraph
from code_analysis.walk import (
    walk_backward_from_sinks,
    walk_bidirectional,
    walk_forward_from_entry_points,
)


def _edge(caller: str, callee: str, confidence: float = 0.7) -> CallEdge:
    return CallEdge(caller=caller, callee=callee, file_path=f"{caller}.py",
                     line=1, confidence=confidence, kind="direct")


def _chain_graph() -> CallGraph:
    """A -> B -> C -> sink (locally-classified). D -> E (unrelated, no sink)."""
    edges = [
        _edge("app.A", "app.B"),
        _edge("app.B", "app.C"),
        _edge("app.C", "app.sink_method"),
        _edge("app.D", "app.E"),
    ]
    return CallGraph(
        nodes=["app.A", "app.B", "app.C", "app.sink_method", "app.D", "app.E"],
        call_edges=edges,
        reference_edges=[],
        entry_points=["app.A"],
        sinks={"app.sink_method": ["89"]},
        file_symbols={
            "app.A": ["app.A"], "app.B": ["app.B"], "app.C": ["app.C"],
            "app.sink_method": ["app.sink_method"], "app.D": ["app.D"], "app.E": ["app.E"],
        },
        symbol_files={
            "app.A": "A.py", "app.B": "B.py", "app.C": "C.py",
            "app.sink_method": "sink.py", "app.D": "D.py", "app.E": "E.py",
        },
    )


class TestWalkBackwardFromSinks:
    def test_finds_all_files_in_the_call_chain(self):
        graph = _chain_graph()
        files = walk_backward_from_sinks(graph, "89", max_hops=5)
        assert files == {"A.py", "B.py", "C.py", "sink.py"}
        assert "D.py" not in files
        assert "E.py" not in files

    def test_max_hops_limits_depth(self):
        graph = _chain_graph()
        # hop 0: sink.py itself. hop 1: C (direct caller of sink).
        files = walk_backward_from_sinks(graph, "89", max_hops=1)
        assert files == {"sink.py", "C.py"}
        assert "B.py" not in files

    def test_min_confidence_filters_low_confidence_edges(self):
        edges = [
            _edge("app.A", "app.sink_method", confidence=0.2),
        ]
        graph = CallGraph(
            nodes=["app.A", "app.sink_method"], call_edges=edges, reference_edges=[],
            entry_points=[], sinks={"app.sink_method": ["89"]},
            file_symbols={"app.A": ["app.A"], "app.sink_method": ["app.sink_method"]},
            symbol_files={"app.A": "A.py", "app.sink_method": "sink.py"},
        )
        files = walk_backward_from_sinks(graph, "89", max_hops=5, min_confidence=0.3)
        assert files == {"sink.py"}  # sink.py itself is the seed, A.py filtered out

    def test_empty_sinks_returns_empty_set(self):
        graph = CallGraph(
            nodes=["app.A"], call_edges=[], reference_edges=[], entry_points=[],
            sinks={}, file_symbols={}, symbol_files={},
        )
        assert walk_backward_from_sinks(graph, "89") == set()

    def test_matches_external_sink_never_locally_classified(self):
        # cursor.execute is never a locally-defined symbol -- it must still
        # be found via direct call-edge callee matching (the primary path).
        edges = [_edge("app.UserService.save", "cursor.execute")]
        graph = CallGraph(
            nodes=["app.UserService.save"], call_edges=edges, reference_edges=[],
            entry_points=[], sinks={},  # no locally-classified sinks at all
            file_symbols={"app.UserService.save": ["app.UserService.save"]},
            symbol_files={"app.UserService.save": "service.py"},
        )
        files = walk_backward_from_sinks(graph, "89", max_hops=5)
        assert "service.py" in files


class TestWalkForwardFromEntryPoints:
    def test_finds_reachable_files_from_entry_point(self):
        graph = _chain_graph()
        files = walk_forward_from_entry_points(graph, max_hops=5)
        assert files == {"A.py", "B.py", "C.py", "sink.py"}
        assert "D.py" not in files

    def test_no_entry_points_returns_empty_set(self):
        graph = CallGraph(
            nodes=["app.A"], call_edges=[], reference_edges=[], entry_points=[],
            sinks={}, file_symbols={}, symbol_files={},
        )
        assert walk_forward_from_entry_points(graph) == set()


class TestWalkBidirectional:
    def test_returns_intersection_when_both_have_results(self):
        graph = _chain_graph()  # A is both entry point and precedes the sink
        files = walk_bidirectional(graph, "89", max_hops=5)
        assert files == {"A.py", "B.py", "C.py", "sink.py"}

    def test_falls_back_to_backward_when_forward_empty(self):
        graph = _chain_graph()
        graph.entry_points = []  # no entry points -> forward walk is empty
        files = walk_bidirectional(graph, "89", max_hops=5)
        assert files == {"A.py", "B.py", "C.py", "sink.py"}
