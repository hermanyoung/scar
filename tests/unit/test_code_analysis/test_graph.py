"""Tests for reference graph and PageRank."""

import pytest

from code_analysis.graph import build_reference_graph, compute_pagerank
from code_analysis.models import ModuleInfo, ReferenceGraph, ReferenceEdge, SymbolInfo, SymbolKind


def _make_module(path: str, imports: list[str], classes: list[str] | None = None) -> ModuleInfo:
    cls_list = []
    if classes:
        for name in classes:
            cls_list.append(SymbolInfo(
                name=name, kind=SymbolKind.CLASS,
                qualified_name=f"{path.replace('/', '.').rstrip('.py')}.{name}",
                line=1,
            ))
    return ModuleInfo(
        path=path, language="python", lines=10,
        imports=imports, classes=cls_list, functions=[], constants=[],
    )


class TestBuildReferenceGraph:
    def test_empty_modules(self):
        graph = build_reference_graph([])
        assert graph.nodes == []
        assert graph.edges == []

    def test_import_creates_edge(self):
        modules = [
            _make_module("app.py", imports=["utils"]),
            _make_module("utils.py", imports=[]),
        ]
        graph = build_reference_graph(modules)
        assert len(graph.edges) >= 1
        edge_pairs = [(e.source, e.target) for e in graph.edges]
        assert ("app", "utils") in edge_pairs

    def test_unresolved_import_no_edge(self):
        modules = [
            _make_module("src/app.py", imports=["external_lib"]),
        ]
        graph = build_reference_graph(modules)
        # external_lib is not a known module, no edge created
        assert len(graph.edges) == 0


class TestPageRank:
    def test_empty_graph(self):
        graph = ReferenceGraph(nodes=[], edges=[])
        ranks = compute_pagerank(graph)
        assert ranks == {}

    def test_single_node(self):
        graph = ReferenceGraph(nodes=["A"], edges=[])
        ranks = compute_pagerank(graph)
        assert ranks == {"A": 1.0}

    def test_linear_chain(self):
        # A -> B -> C: C should rank highest (most "linked to")
        graph = ReferenceGraph(
            nodes=["A", "B", "C"],
            edges=[
                ReferenceEdge(source="A", target="B"),
                ReferenceEdge(source="B", target="C"),
            ],
        )
        ranks = compute_pagerank(graph)
        assert ranks["C"] > ranks["A"]

    def test_hub_node_ranks_highest(self):
        # A, B, C all point to D: D should rank highest
        graph = ReferenceGraph(
            nodes=["A", "B", "C", "D"],
            edges=[
                ReferenceEdge(source="A", target="D"),
                ReferenceEdge(source="B", target="D"),
                ReferenceEdge(source="C", target="D"),
            ],
        )
        ranks = compute_pagerank(graph)
        assert ranks["D"] == 1.0

    def test_scores_normalized_to_max_1(self):
        graph = ReferenceGraph(
            nodes=["A", "B"],
            edges=[ReferenceEdge(source="A", target="B")],
        )
        ranks = compute_pagerank(graph)
        assert max(ranks.values()) == 1.0
        assert all(0.0 <= v <= 1.0 for v in ranks.values())
