"""Project-root resolution for code_analysis — a dependency-free leaf module.

Lives apart from ``__init__`` so that leaf modules (``store``, ``sinks``) can
resolve config paths via ``MODULE_ROOT`` without importing the package root,
which would create an import cycle (``__init__`` → ``call_graph`` → ``store`` →
``__init__``).
"""

from __future__ import annotations

from pathlib import Path


def _find_project_root() -> Path:
    """Walk up from this file to find the directory containing .project_root.

    WARNING: This is intentionally duplicated from security_review/__init__.py
    and scar.py -- code_analysis must resolve config paths without depending
    on the security_review package (it is also used standalone by code_quality).
    """
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / ".project_root").exists():
            return parent
    raise RuntimeError(
        "Cannot find .project_root marker. "
        "Ensure .project_root exists at the repository root."
    )


# Canonical project root -- used to locate config/taxonomy/sinks.yaml.
MODULE_ROOT = _find_project_root()
