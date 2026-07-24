"""SQLite persistence for call graphs and findings.

Enables cross-run incrementalism: unchanged files are not re-parsed, and
findings are fingerprinted so a report can distinguish new/recurring/resolved
across runs. The database lives under SCAR's own var/cache/graphs/ (never
inside the target repo being reviewed) -- see target_cache_dir().
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import structlog

from code_analysis import MODULE_ROOT
from code_analysis.models import CallEdge, CallGraph, ReferenceEdge

logger = structlog.get_logger()

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS file_cache (
    file_path    TEXT PRIMARY KEY,
    sha256       TEXT NOT NULL,
    language     TEXT NOT NULL,
    parsed_at    TEXT NOT NULL DEFAULT (datetime('now')),
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
    caller     TEXT NOT NULL,
    callee     TEXT NOT NULL,
    file_path  TEXT NOT NULL,
    line       INTEGER NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    kind       TEXT NOT NULL DEFAULT 'direct',
    PRIMARY KEY (caller, callee, line)
);
CREATE INDEX IF NOT EXISTS ix_edges_callee ON call_edges(callee);
CREATE INDEX IF NOT EXISTS ix_edges_caller ON call_edges(caller);
CREATE INDEX IF NOT EXISTS ix_edges_file ON call_edges(file_path);

CREATE TABLE IF NOT EXISTS reference_edges (
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    PRIMARY KEY (source, target)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at  TEXT,
    repo_root    TEXT NOT NULL,
    git_sha      TEXT,
    scar_version TEXT NOT NULL,
    config_hash  TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    fingerprint    TEXT NOT NULL,
    run_id         TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    cwe_id         TEXT NOT NULL,
    severity       TEXT NOT NULL,
    file_path      TEXT NOT NULL,
    line_number    INTEGER NOT NULL,
    symbol         TEXT,
    message        TEXT NOT NULL,
    confidence     REAL NOT NULL,
    status         TEXT NOT NULL DEFAULT 'open',
    first_seen_run TEXT,
    last_seen_run  TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (fingerprint, run_id)
);
CREATE INDEX IF NOT EXISTS ix_findings_cwe ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS ix_findings_file ON findings(file_path);
"""


def target_cache_dir(target_root: Path) -> Path:
    """Per-target cache directory under SCAR's own var/cache/graphs/.

    SCAR never writes into the repository it scans (plan 021). The key is
    derived from the resolved target path, so repeat runs against the same
    target reuse the same incremental graph DB.
    """
    key = hashlib.sha256(str(Path(target_root).resolve()).encode("utf-8")).hexdigest()[:16]
    cache_dir = MODULE_ROOT / "var" / "cache" / "graphs" / key
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


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

    def __enter__(self) -> "GraphStore":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _ensure_version(self) -> None:
        row = self._conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        if row is None:
            self._conn.execute("INSERT INTO schema_version(version) VALUES(?)", (SCHEMA_VERSION,))
            self._conn.commit()

    def file_needs_reindex(self, file_path: str, sha256: str) -> bool:
        """True if a file needs re-parsing (content changed or not cached)."""
        row = self._conn.execute(
            "SELECT sha256 FROM file_cache WHERE file_path=?", (file_path,),
        ).fetchone()
        return row is None or row[0] != sha256

    def delete_file_data(self, file_path: str) -> None:
        """Remove all symbols and edges for a file (CASCADE from file_cache)."""
        self._conn.execute("DELETE FROM symbols WHERE file_path=?", (file_path,))
        self._conn.execute("DELETE FROM call_edges WHERE file_path=?", (file_path,))
        self._conn.execute("DELETE FROM file_cache WHERE file_path=?", (file_path,))

    def upsert_file(
        self, file_path: str, sha256: str, language: str,
        symbol_count: int, edge_count: int,
    ) -> None:
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
        """, [(e.caller, e.callee, e.file_path, e.line, e.confidence, e.kind) for e in edges])

    def insert_reference_edges(self, edges: list[ReferenceEdge]) -> None:
        self._conn.executemany("""
            INSERT OR IGNORE INTO reference_edges(source, target) VALUES(?, ?)
        """, [(e.source, e.target) for e in edges])

    def commit(self) -> None:
        self._conn.commit()

    def load_call_graph(self) -> CallGraph:
        """Reconstruct a CallGraph from the persisted data."""
        symbol_rows = self._conn.execute(
            "SELECT qualified_name, file_path, is_entry_point, is_sink, cwe_tags FROM symbols",
        ).fetchall()

        nodes: list[str] = []
        entry_points: list[str] = []
        sinks: dict[str, list[str]] = {}
        file_symbols: dict[str, list[str]] = {}
        symbol_files: dict[str, str] = {}

        for qn, fp, is_ep, is_s, cwe_json in symbol_rows:
            nodes.append(qn)
            symbol_files[qn] = fp
            file_symbols.setdefault(fp, []).append(qn)
            if is_ep:
                entry_points.append(qn)
            if is_s:
                sinks[qn] = json.loads(cwe_json)

        call_rows = self._conn.execute(
            "SELECT caller, callee, file_path, line, confidence, kind FROM call_edges",
        ).fetchall()
        call_edges = [
            CallEdge(caller=r[0], callee=r[1], file_path=r[2], line=r[3], confidence=r[4], kind=r[5])
            for r in call_rows
        ]

        ref_rows = self._conn.execute("SELECT source, target FROM reference_edges").fetchall()
        ref_edges = [ReferenceEdge(source=r[0], target=r[1]) for r in ref_rows]

        # Union in call-edge endpoints not already covered by a symbol row,
        # mirroring build_call_graph()'s own union step (see call_graph.py) --
        # otherwise a reloaded graph would lose resolvability for nodes that
        # only ever existed as a call edge (e.g. pyan's module-level node).
        for edge in call_edges:
            if edge.caller not in symbol_files:
                symbol_files[edge.caller] = edge.file_path
                file_symbols.setdefault(edge.file_path, []).append(edge.caller)
                nodes.append(edge.caller)

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
        """Return files that need re-indexing (new or modified).

        Also deletes cached data for files present in the cache but absent
        from file_shas (deleted since the last run).
        """
        changed = [fp for fp, sha in file_shas.items() if self.file_needs_reindex(fp, sha)]

        cached = {row[0] for row in self._conn.execute("SELECT file_path FROM file_cache").fetchall()}
        deleted = cached - set(file_shas.keys())
        for fp in deleted:
            self.delete_file_data(fp)
        if deleted:
            self.commit()

        return changed

    # -- Cross-run finding tracking ------------------------------------------

    def start_run(self, run_id: str, repo_root: str, scar_version: str, config_hash: str | None = None) -> None:
        self._conn.execute("""
            INSERT OR REPLACE INTO runs(run_id, repo_root, scar_version, config_hash)
            VALUES(?, ?, ?, ?)
        """, (run_id, repo_root, scar_version, config_hash))

    def finish_run(self, run_id: str) -> None:
        self._conn.execute(
            "UPDATE runs SET finished_at=datetime('now') WHERE run_id=?", (run_id,),
        )

    def first_seen_run(self, fingerprint: str) -> str | None:
        """The earliest run_id that recorded this fingerprint, across all runs, or None if new."""
        row = self._conn.execute(
            "SELECT run_id FROM findings WHERE fingerprint=? ORDER BY created_at ASC LIMIT 1",
            (fingerprint,),
        ).fetchone()
        return row[0] if row else None

    def record_finding(
        self, fingerprint: str, run_id: str, cwe_id: str, severity: str,
        file_path: str, line_number: int, message: str, confidence: float,
        symbol: str | None = None,
    ) -> str:
        """Record a finding for this run. Returns "new" or "recurring"."""
        first_seen = self.first_seen_run(fingerprint)
        status = "recurring" if first_seen else "new"
        self._conn.execute("""
            INSERT OR REPLACE INTO findings(
                fingerprint, run_id, cwe_id, severity, file_path, line_number,
                symbol, message, confidence, status, first_seen_run, last_seen_run
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
        """, (
            fingerprint, run_id, cwe_id, severity, file_path, line_number,
            symbol, message, confidence, first_seen or run_id, run_id,
        ))
        return status
