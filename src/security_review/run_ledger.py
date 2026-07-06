"""Append-only JSONL event ledger for a single run.

One line per event, flushed per call — crash-safe by construction.
The ledger is best-effort: a ledger write failure must never kill the
pipeline (it logs at WARNING and continues).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class RunLedger:
    """Append-only events.jsonl writer for one pipeline run."""

    def __init__(self, path: Path):
        self._path = path

    def append(self, kind: str, **fields) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            **fields,
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError as e:
            logger.warning("ledger.write_failed", path=str(self._path), error=str(e))
