"""Tests for SQLite call-graph persistence."""

from __future__ import annotations

from pathlib import Path

import pytest

from code_analysis.models import CallEdge, ReferenceEdge
from code_analysis.store import GraphStore, init_target_gitignore


@pytest.fixture
def store(tmp_path: Path) -> GraphStore:
    with GraphStore(tmp_path / "graph.db") as s:
        yield s


def _symbol(qn: str, file_path: str, **kwargs) -> dict:
    return {
        "qualified_name": qn, "file_path": file_path, "kind": "method",
        "line_number": 1, **kwargs,
    }


class TestFileNeedsReindex:
    def test_new_file_needs_reindex(self, store: GraphStore):
        assert store.file_needs_reindex("app.py", "sha-abc") is True

    def test_unchanged_file_does_not_need_reindex(self, store: GraphStore):
        store.upsert_file("app.py", "sha-abc", "python", 1, 0)
        store.commit()
        assert store.file_needs_reindex("app.py", "sha-abc") is False

    def test_modified_file_needs_reindex(self, store: GraphStore):
        store.upsert_file("app.py", "sha-abc", "python", 1, 0)
        store.commit()
        assert store.file_needs_reindex("app.py", "sha-def") is True


class TestRoundTrip:
    def test_insert_and_load_call_graph(self, store: GraphStore):
        store.upsert_file("app/service.py", "sha1", "python", 2, 1)
        store.insert_symbols([
            _symbol("app.service.Service.save", "app/service.py", is_sink=True, cwe_tags=["89"]),
            _symbol("app.service.Controller.create", "app/service.py", is_entry_point=True),
        ])
        store.insert_call_edges([
            CallEdge(caller="app.service.Controller.create", callee="app.service.Service.save",
                     file_path="app/service.py", line=5, confidence=0.9, kind="direct"),
        ])
        store.insert_reference_edges([ReferenceEdge(source="app.service", target="app.other")])
        store.commit()

        graph = store.load_call_graph()

        assert "app.service.Service.save" in graph.symbol_files
        assert graph.symbol_files["app.service.Service.save"] == "app/service.py"
        assert graph.sinks["app.service.Service.save"] == ["89"]
        assert "app.service.Controller.create" in graph.entry_points
        assert len(graph.call_edges) == 1
        assert graph.call_edges[0].callee == "app.service.Service.save"
        assert len(graph.reference_edges) == 1

    def test_call_edge_endpoint_without_symbol_row_still_resolves(self, store: GraphStore):
        # A caller with no symbols row at all (e.g. only ever seen as a call
        # edge) must still resolve to its file when the graph is reloaded.
        store.insert_call_edges([
            CallEdge(caller="app.mod.func", callee="external.thing",
                     file_path="app/mod.py", line=3, confidence=0.7, kind="direct"),
        ])
        store.commit()
        graph = store.load_call_graph()
        assert graph.symbol_files["app.mod.func"] == "app/mod.py"


class TestDeleteFileData:
    def test_delete_removes_symbols_and_edges(self, store: GraphStore):
        store.upsert_file("app.py", "sha1", "python", 1, 1)
        store.insert_symbols([_symbol("app.func", "app.py")])
        store.insert_call_edges([
            CallEdge(caller="app.func", callee="app.other", file_path="app.py",
                     line=1, confidence=0.7, kind="direct"),
        ])
        store.commit()

        store.delete_file_data("app.py")
        store.commit()

        graph = store.load_call_graph()
        assert graph.symbol_files == {}
        assert graph.call_edges == []


class TestGetChangedFiles:
    def test_detects_new_modified_and_deleted_files(self, store: GraphStore):
        store.upsert_file("unchanged.py", "sha-same", "python", 1, 0)
        store.upsert_file("modified.py", "sha-old", "python", 1, 0)
        store.upsert_file("deleted.py", "sha-gone", "python", 1, 0)
        store.commit()

        changed = store.get_changed_files({
            "unchanged.py": "sha-same",
            "modified.py": "sha-new",
            "new.py": "sha-brand-new",
        })

        assert set(changed) == {"modified.py", "new.py"}
        # deleted.py's cached data should have been removed
        cached_files = {row[0] for row in store._conn.execute("SELECT file_path FROM file_cache")}
        assert "deleted.py" not in cached_files
        assert "unchanged.py" in cached_files


class TestFindingTracking:
    def test_first_recording_is_new(self, store: GraphStore):
        store.start_run("run1", "/repo", "1.0.0")
        status = store.record_finding("fp1", "run1", "CWE-89", "HIGH", "app.py", 10, "msg", 0.9)
        assert status == "new"

    def test_second_run_same_fingerprint_is_recurring(self, store: GraphStore):
        store.start_run("run1", "/repo", "1.0.0")
        store.record_finding("fp1", "run1", "CWE-89", "HIGH", "app.py", 10, "msg", 0.9)
        store.commit()

        store.start_run("run2", "/repo", "1.0.0")
        status = store.record_finding("fp1", "run2", "CWE-89", "HIGH", "app.py", 10, "msg", 0.9)
        assert status == "recurring"

    def test_first_seen_run_preserved_across_runs(self, store: GraphStore):
        store.start_run("run1", "/repo", "1.0.0")
        store.record_finding("fp1", "run1", "CWE-89", "HIGH", "app.py", 10, "msg", 0.9)
        store.commit()
        store.start_run("run2", "/repo", "1.0.0")
        store.record_finding("fp1", "run2", "CWE-89", "HIGH", "app.py", 10, "msg", 0.9)
        store.commit()

        row = store._conn.execute(
            "SELECT first_seen_run, last_seen_run FROM findings WHERE fingerprint=? AND run_id=?",
            ("fp1", "run2"),
        ).fetchone()
        assert row == ("run1", "run2")

    def test_different_fingerprint_is_new_even_in_same_run(self, store: GraphStore):
        store.start_run("run1", "/repo", "1.0.0")
        store.record_finding("fp1", "run1", "CWE-89", "HIGH", "app.py", 10, "msg", 0.9)
        status = store.record_finding("fp2", "run1", "CWE-89", "HIGH", "app.py", 20, "msg2", 0.9)
        assert status == "new"


class TestInitTargetGitignore:
    def test_creates_scar_dir_with_gitignore(self, tmp_path: Path):
        init_target_gitignore(tmp_path)
        assert (tmp_path / ".scar").is_dir()
        assert (tmp_path / ".scar" / ".gitignore").read_text() == "*\n"

    def test_idempotent(self, tmp_path: Path):
        init_target_gitignore(tmp_path)
        init_target_gitignore(tmp_path)  # must not raise
        assert (tmp_path / ".scar" / ".gitignore").exists()
