"""Security code review module with SAST + LLM pipeline."""
from pathlib import Path

__version__ = "1.0.0"


def _find_project_root() -> Path:
    """Walk up from this file to find the directory containing .project_root.

    WARNING: This is intentionally duplicated in scar.py (the CLI entry point).
    scar.py must resolve the root BEFORE sys.path includes src/, so it cannot
    import this module. If you change the logic here, update scar.py to match.
    """
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / ".project_root").exists():
            return parent
    raise RuntimeError(
        "Cannot find .project_root marker. "
        "Ensure .project_root exists at the repository root."
    )


# Canonical project root — used by all modules that need config/prompts/taxonomy paths.
MODULE_ROOT = _find_project_root()
