#!/usr/bin/env python3
"""SCAR — Security Code AI Review.

Usage:
    python scar.py review --target /path/to/codebase
    python scar.py review --target . --provider copilot:claude-opus-4.6
    python scar.py review --target . --mode sast
    python scar.py health-check
    python scar.py list-models
    python scar.py list-models --provider anthropic --all
    python scar.py list-models --foundry
    python scar.py list-models --foundry --catalog --publisher Anthropic
    python scar.py list-rules
    python scar.py test-rule --cwe 89 --target ../my-app/
    python scar.py test-cwe --cwe 863 --target ../my-app/
    python scar.py test-providers --copilot
    python scar.py reports
    python scar.py reports --show d8e9f8db
    python scar.py reports --compare id1 id2
    python scar.py eval
    python scar.py eval --provider copilot:claude-opus
"""
from __future__ import annotations

import sys
from pathlib import Path


def _find_project_root() -> Path:
    """Walk up from this file to find the directory containing .project_root.

    WARNING: This is intentionally duplicated from security_review.__init__.
    scar.py must resolve the root BEFORE sys.path is configured (chicken-and-egg
    bootstrap — we need the root to add src/ to sys.path, but the module lives
    under src/). If you change the logic here, update security_review.__init__
    to match, and vice versa.
    """
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / ".project_root").exists():
            return parent
    raise RuntimeError(
        "Cannot find .project_root marker. "
        "Ensure .project_root exists at the repository root."
    )


PROJECT_ROOT = _find_project_root()
sys.path.insert(0, str(PROJECT_ROOT / "src"))


if __name__ == "__main__":
    from security_review.cli import cli
    cli()
