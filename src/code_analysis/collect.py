"""File discovery for code analysis.

Single implementation of source file collection with scope, exclude,
and extension filtering.
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path


EXCLUDE_DEFAULTS: list[str] = [
    "obj/",
    "bin/",
    "Migrations/",
    "__pycache__/",
    ".venv/",
    "node_modules/",
    ".git/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".ruff_cache/",
    "*.designer.cs",
    "*.g.cs",
]

ALL_EXTENSIONS: set[str] = {".py", ".cs"}


def collect_files(
    root: Path,
    *,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    extensions: set[str] | None = None,
) -> list[Path]:
    """Discover source files under root.

    Args:
        root: Repository or project root directory.
        scope: Directory/glob patterns to include. None = entire root.
        exclude: Patterns to skip. None = EXCLUDE_DEFAULTS.
        extensions: File extensions to include (e.g. {".py", ".cs"}).
                   None = all known language extensions.

    Returns:
        Sorted list of absolute file paths.
    """
    exclude = exclude if exclude is not None else EXCLUDE_DEFAULTS
    extensions = extensions or ALL_EXTENSIONS

    if scope:
        files: list[Path] = []
        for pattern in scope:
            candidate = root / pattern
            if candidate.is_file() and candidate.suffix in extensions:
                files.append(candidate)
            elif candidate.is_dir():
                for ext in extensions:
                    files.extend(candidate.rglob(f"*{ext}"))
            elif "*" in pattern or "?" in pattern:
                files.extend(
                    f for f in root.glob(pattern) if f.suffix in extensions
                )
        files = list(set(files))
    else:
        files = []
        for ext in extensions:
            files.extend(root.rglob(f"*{ext}"))

    result = []
    for f in sorted(files):
        rel = str(f.relative_to(root))
        if any(_matches_exclude(rel, exc) for exc in exclude):
            continue
        result.append(f)
    return result


def _matches_exclude(rel_path: str, pattern: str) -> bool:
    """Check if a relative path matches an exclusion pattern."""
    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        return rel_path.startswith(pattern) or rel_path.startswith(prefix)
    if "*" in pattern or "?" in pattern or "[" in pattern:
        return fnmatch(rel_path, pattern) or fnmatch(rel_path.split("/")[-1], pattern)
    return rel_path.startswith(pattern)
