"""Atomic file-write helper shared by checkpointing, streaming, and tracing.

The repo previously had no atomic-write utility (tracing.write_trace did a
plain open/write). Checkpoint files must never be observable half-written —
a killed run would otherwise leave a corrupt state/*.json that blocks
--resume — so all JSON artifacts that may be read back go through here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def atomic_write_json(path: Path, data: Any, *, indent: int = 2) -> None:
    """Write JSON to ``path`` atomically: write ``.tmp`` then ``os.replace``.

    os.replace is atomic on POSIX and Windows for same-filesystem paths, so
    a reader (or a resumed run) can never observe a partial file. Parent
    directories are created as needed. Non-serialisable values fall back to
    ``str`` (same policy tracing already used).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, default=str)
    os.replace(tmp, path)
