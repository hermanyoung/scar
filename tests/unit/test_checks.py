"""Tests for the CWE check registry (Plan 019 WP-G / plan 002 §2.1 remainder)."""
from __future__ import annotations

from code_analysis.models import CallEdge, CallGraph
from security_review.checks import (
    CWECheck,
    load_cwe_checks,
    select_cwe_checks_for_diff,
    select_files_for_check,
    select_files_for_cwe,
)
from security_review.models.inventory import FileEntry


def _entry(path: str, language: str = "csharp") -> FileEntry:
    return FileEntry(path=path, language=language, size_bytes=100,
                     security_weight=1, estimated_tokens=25)


def test_load_cwe_checks_returns_checks():
    checks = load_cwe_checks()
    assert len(checks) > 0


def test_every_check_has_prompt_and_file_types():
    for check in load_cwe_checks():
        assert check.check_prompt, f"CWE-{check.cwe_id} has an empty check prompt"
        assert check.file_types, f"CWE-{check.cwe_id} has no file_types"


def test_863_check_contains_severity_rubric():
    checks = {c.cwe_id: c for c in load_cwe_checks()}
    assert "863" in checks
    assert "Severity rubric" in checks["863"].check_prompt


def test_select_files_for_check_matches_controller_and_excludes_readme():
    check = CWECheck(
        cwe_id="862", name="Missing Authorization", detection="llm",
        file_types=["controller"], check_prompt="Check authorization.",
    )
    files = [
        _entry("Controllers/UserController.cs"),
        _entry("README.md", language="markdown"),
    ]

    selected = select_files_for_check(check, files)

    paths = [f.path for f in selected]
    assert "Controllers/UserController.cs" in paths
    assert "README.md" not in paths


def test_load_cwe_checks_returns_jwt_cwe_entries():
    checks = {c.cwe_id: c for c in load_cwe_checks()}
    for cwe_id in ("321", "345", "757"):
        assert cwe_id in checks, f"CWE-{cwe_id} not returned by load_cwe_checks()"
        assert checks[cwe_id].detection in ("llm", "sast+llm")
        assert checks[cwe_id].check_prompt


def test_select_files_for_check_auth_matches_jwt_keywords():
    check = CWECheck(
        cwe_id="345", name="Insufficient Verification of Data Authenticity",
        detection="llm", file_types=["auth"], check_prompt="Check JWT validation.",
    )
    files = [
        _entry("Services/JwtTokenService.cs"),
        _entry("Middleware/BearerAuthHandler.cs"),
        _entry("Models/ClaimsPrincipalFactory.cs"),
        _entry("README.md", language="markdown"),
    ]

    selected = select_files_for_check(check, files)

    paths = [f.path for f in selected]
    assert "Services/JwtTokenService.cs" in paths
    assert "Middleware/BearerAuthHandler.cs" in paths
    assert "Models/ClaimsPrincipalFactory.cs" in paths
    assert "README.md" not in paths


def test_load_cwe_checks_returns_walk_config_for_cwe_89():
    checks = {c.cwe_id: c for c in load_cwe_checks()}
    assert checks["89"].walk_direction == "backward"
    assert checks["89"].sink_patterns == ["89"]
    assert checks["89"].max_hops > 0


def test_select_files_for_cwe_with_no_call_graph_falls_back_to_keyword():
    check = CWECheck(
        cwe_id="862", name="Missing Authorization", detection="llm",
        file_types=["controller"], check_prompt="Check authorization.",
        walk_direction="forward",
    )
    files = [_entry("Controllers/UserController.cs"), _entry("README.md", language="markdown")]

    selected, telemetry = select_files_for_cwe(check, files, call_graph=None)

    assert selected == select_files_for_check(check, files)
    assert telemetry.method == "keyword"
    assert telemetry.graph_files_count == 0


def test_select_files_for_cwe_unions_graph_and_keyword_files():
    check = CWECheck(
        cwe_id="89", name="SQL Injection", detection="sast+llm",
        file_types=["model"], check_prompt="Check for SQL injection.",
        walk_direction="backward", max_hops=5, sink_patterns=["89"],
    )
    files = [
        _entry("Models/UserModel.cs"),          # matched by keyword ("model")
        _entry("Infrastructure/DataStore.cs"),  # NOT matched by keyword, only by graph walk
        _entry("Unrelated/Logger.cs"),           # matched by neither
    ]
    graph = CallGraph(
        nodes=["App.DataStore.Insert", "App.DataStore.Insert.sink"],
        call_edges=[CallEdge(
            caller="App.DataStore.Insert", callee="cursor.execute",
            file_path="Infrastructure/DataStore.cs", line=10,
            confidence=0.9, kind="direct",
        )],
        reference_edges=[], entry_points=[], sinks={},
        file_symbols={"Infrastructure/DataStore.cs": ["App.DataStore.Insert"]},
        symbol_files={"App.DataStore.Insert": "Infrastructure/DataStore.cs"},
    )

    selected, telemetry = select_files_for_cwe(check, files, call_graph=graph)
    paths = {f.path for f in selected}

    assert "Models/UserModel.cs" in paths       # keyword match preserved
    assert "Infrastructure/DataStore.cs" in paths  # graph-walk-only file included
    assert "Unrelated/Logger.cs" not in paths
    assert telemetry.method == "graph"
    assert telemetry.graph_files_count == 1
    assert telemetry.total_files_selected == len(selected)


def test_select_files_for_cwe_sorts_by_pagerank_descending():
    check = CWECheck(
        cwe_id="89", name="SQL Injection", detection="sast+llm",
        file_types=["model"], check_prompt="Check for SQL injection.",
        walk_direction="backward", max_hops=5, sink_patterns=["89"],
    )
    files = [_entry("Low/Low.cs"), _entry("High/High.cs")]
    graph = CallGraph(
        nodes=["Low.M", "High.M"],
        call_edges=[
            CallEdge(caller="Low.M", callee="cursor.execute", file_path="Low/Low.cs",
                      line=1, confidence=0.9, kind="direct"),
            CallEdge(caller="High.M", callee="cursor.execute", file_path="High/High.cs",
                      line=1, confidence=0.9, kind="direct"),
        ],
        reference_edges=[], entry_points=[], sinks={},
        file_symbols={"Low/Low.cs": ["Low.M"], "High/High.cs": ["High.M"]},
        symbol_files={"Low.M": "Low/Low.cs", "High.M": "High/High.cs"},
    )
    pagerank = {"Low.M": 0.1, "High.M": 0.9}

    selected, _telemetry = select_files_for_cwe(check, files, call_graph=graph, pagerank=pagerank)

    assert [f.path for f in selected] == ["High/High.cs", "Low/Low.cs"]


def _diff_graph() -> CallGraph:
    """entry.py (entry point) -> mid.py -> sink.py (calls cursor.execute)."""
    edges = [
        CallEdge(caller="app.entry.handler", callee="app.mid.process",
                 file_path="app/entry.py", line=1, confidence=0.9, kind="direct"),
        CallEdge(caller="app.mid.process", callee="cursor.execute",
                 file_path="app/mid.py", line=1, confidence=0.9, kind="direct"),
    ]
    return CallGraph(
        nodes=["app.entry.handler", "app.mid.process"],
        call_edges=edges, reference_edges=[],
        entry_points=["app.entry.handler"], sinks={},
        file_symbols={"app/entry.py": ["app.entry.handler"], "app/mid.py": ["app.mid.process"]},
        symbol_files={"app.entry.handler": "app/entry.py", "app.mid.process": "app/mid.py"},
    )


class TestSelectCweChecksForDiff:
    def test_no_changed_files_returns_all_checks(self):
        checks = [CWECheck(cwe_id="89", name="x", detection="llm", file_types=[], check_prompt="p")]
        graph = _diff_graph()
        assert select_cwe_checks_for_diff(checks, [], graph) == checks

    def test_no_call_edges_returns_all_checks(self):
        checks = [CWECheck(cwe_id="89", name="x", detection="llm", file_types=[], check_prompt="p")]
        empty_graph = CallGraph(nodes=[], call_edges=[], reference_edges=[],
                                entry_points=[], sinks={}, file_symbols={}, symbol_files={})
        assert select_cwe_checks_for_diff(checks, ["app/mid.py"], empty_graph) == checks

    def test_forward_check_included_when_entry_point_in_blast_radius(self):
        auth_check = CWECheck(cwe_id="862", name="Missing Authorization", detection="llm",
                              file_types=["controller"], check_prompt="p", walk_direction="forward")
        graph = _diff_graph()

        selected = select_cwe_checks_for_diff([auth_check], ["app/entry.py"], graph)
        assert auth_check in selected

    def test_backward_check_included_when_sink_reachable_from_changed_file(self):
        sqli_check = CWECheck(cwe_id="89", name="SQL Injection", detection="sast+llm",
                              file_types=["model"], check_prompt="p",
                              walk_direction="backward", sink_patterns=["89"])
        graph = _diff_graph()

        selected = select_cwe_checks_for_diff([sqli_check], ["app/mid.py"], graph)
        assert sqli_check in selected

    def test_backward_check_excluded_when_change_is_unrelated(self):
        sqli_check = CWECheck(cwe_id="89", name="SQL Injection", detection="sast+llm",
                              file_types=["model"], check_prompt="p",
                              walk_direction="backward", sink_patterns=["89"])
        # A second check that DOES match the changed file keeps the overall
        # result non-empty, so the "fall back to all" safety net (triggered
        # only when nothing at all is affected) doesn't mask this assertion.
        unrelated_check = CWECheck(cwe_id="79", name="XSS", detection="llm",
                                    file_types=["unrelated"], check_prompt="p")
        graph = _diff_graph()

        selected = select_cwe_checks_for_diff(
            [sqli_check, unrelated_check], ["unrelated/file.py"], graph, max_hops=0,
        )
        assert sqli_check not in selected

    def test_keyword_only_check_included_when_blast_file_matches_file_types(self):
        controller_check = CWECheck(cwe_id="601", name="Open Redirect", detection="llm",
                                    file_types=["controller"], check_prompt="p")
        graph = _diff_graph()

        selected = select_cwe_checks_for_diff(
            [controller_check], ["Controllers/Home.py"], graph,
        )
        assert controller_check in selected
