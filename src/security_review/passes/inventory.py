"""Pass 1: File discovery, language detection, security-weight scoring."""
from __future__ import annotations

import re
from pathlib import Path

import structlog

from security_review.models.coverage import CoverageReport, FileCoverage
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.state import PipelineState
from security_review.tools.registry import load_tool_specs

logger = structlog.get_logger()

# Directories to always exclude from inventory
EXCLUDE_DIRS = {
    "obj", "bin", "Migrations", "__pycache__", ".venv", "venv",
    "node_modules", ".git", ".vs", ".idea", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "eggs", "worktrees",
}

# File patterns to exclude
_EXCLUDE_FILE_PATTERNS = [
    re.compile(r"\.designer\.cs$", re.IGNORECASE),
    re.compile(r"\.g\.cs$", re.IGNORECASE),
    re.compile(r"\.g\.i\.cs$", re.IGNORECASE),
    re.compile(r"\.AssemblyInfo\.cs$", re.IGNORECASE),
    re.compile(r"\.min\.js$", re.IGNORECASE),
    re.compile(r"\.min\.css$", re.IGNORECASE),
]

# Language detection by extension
EXTENSION_LANGUAGE = {
    ".py": "python",
    ".cs": "csharp",
    ".razor": "csharp",
    ".csproj": "csharp",
    ".sln": "csharp",
    ".json": "config",
    ".yaml": "config",
    ".yml": "config",
    ".toml": "config",
    ".xml": "config",
    ".props": "config",
    ".editorconfig": "config",
    ".dockerfile": "config",
    ".env": "config",
    ".bicep": "config",
    ".bicepparam": "config",
    ".tf": "config",
    ".tfvars": "config",
}

# Patterns that increase security weight
_SECURITY_WEIGHT_PATTERNS = [
    (re.compile(r"Controller", re.IGNORECASE), 3),
    (re.compile(r"def (post|put|patch|delete)\b"), 2),
    (re.compile(r"app\.Map(Get|Post|Put|Delete|Patch)"), 3),
    (re.compile(r"@app\.route"), 2),
    (re.compile(r"@router\.(get|post|put|delete|patch)"), 2),
    (re.compile(r"Process\.Start"), 3),
    (re.compile(r"eval\("), 3),
    (re.compile(r"pickle\.(loads?|dump)"), 3),
    (re.compile(r"BinaryFormatter"), 4),
    (re.compile(r"NetDataContractSerializer"), 4),
    (re.compile(r"subprocess\.(call|run|Popen)"), 2),
    (re.compile(r"os\.(system|popen)"), 2),
    (re.compile(r"SqlCommand|SqlConnection"), 2),
    (re.compile(r"cursor\.execute"), 2),
    (re.compile(r"\[Authorize\]"), 2),
    (re.compile(r"@login_required"), 2),
    (re.compile(r"Depends\("), 2),
    (re.compile(r"(password|secret|api_key|token)\s*=", re.IGNORECASE), 2),
    (re.compile(r"middleware", re.IGNORECASE), 2),
    (re.compile(r"auth", re.IGNORECASE), 1),
    (re.compile(r"crypto", re.IGNORECASE), 2),
    # Config/secrets handling
    (re.compile(r"SecretStr|pydantic_settings|BaseSettings", re.IGNORECASE), 3),
    (re.compile(r"(getenv|environ|\.env)", re.IGNORECASE), 2),
    (re.compile(r"(connection_string|database_url|redis_url)", re.IGNORECASE), 2),
    (re.compile(r"(SESSION_|COOKIE_|CSRF_|CORS_)", re.IGNORECASE), 2),
    # File/upload handling
    (re.compile(r"(upload|multipart|form_data|UploadFile)", re.IGNORECASE), 2),
    (re.compile(r"(open\(|shutil\.(copy|move)|write_text)", re.IGNORECASE), 1),
]

# Rough estimate: 1 token ~ 4 chars
_CHARS_PER_TOKEN = 4


def discover_files(
    target_path: Path,
    max_size: int = 1_048_576,
    exclude: tuple[str, ...] = (),
    include: tuple[str, ...] = (),
) -> list[FileEntry]:
    """Discover source files, detect languages, and compute security weights.

    This is the single file-discovery function used by both run_inventory()
    and CLI commands like test-cwe. One code path, one truth.

    Args:
        target_path: Resolved root directory to scan.
        max_size: Skip files larger than this (bytes).
        exclude: fnmatch globs (relative paths) to exclude. Default empty —
            existing callers are unaffected.
        include: when non-empty, only matching relative paths are kept.

    Returns:
        List of FileEntry sorted by security_weight descending.
    """
    entries: list[FileEntry] = []

    for file_path in _walk_files(target_path, max_size, exclude, include):
        rel_path = str(file_path.relative_to(target_path)).replace("\\", "/")
        ext = file_path.suffix.lower()
        language = EXTENSION_LANGUAGE.get(ext, "other")

        # Check for Dockerfile (no extension)
        if file_path.name.lower().startswith("dockerfile"):
            language = "config"

        size_bytes = file_path.stat().st_size
        estimated_tokens = max(1, size_bytes // _CHARS_PER_TOKEN)

        # Compute security weight
        security_weight = _compute_security_weight(file_path, language)

        entries.append(FileEntry(
            path=rel_path,
            language=language,
            size_bytes=size_bytes,
            security_weight=security_weight,
            estimated_tokens=estimated_tokens,
        ))

    # Sort by security weight descending
    entries.sort(key=lambda e: e.security_weight, reverse=True)
    return entries


async def run_inventory(state: PipelineState) -> None:
    """Execute Pass 1: discover files and build the file manifest."""

    logger.info("pipeline.pass_started", pass_number=1, pass_name="inventory")

    target = state.target_path.resolve()
    if not target.exists():
        from security_review.errors import ConfigurationError
        raise ConfigurationError(
            f"Target path {target} does not exist",
            code="SYS_TARGET_NOT_FOUND",
        )

    max_size = state.config.sast.scanner_max_file_size_bytes
    entries = discover_files(
        target, max_size,
        exclude=tuple(state.config.review.exclude),
        include=tuple(state.config.review.include),
    )

    languages: dict[str, int] = {}
    for entry in entries:
        languages[entry.language] = languages.get(entry.language, 0) + 1

    state.manifest = FileManifest(
        files=entries,
        total_files=len(entries),
        total_tokens=sum(e.estimated_tokens for e in entries),
        languages=languages,
    )

    # Build coverage report
    state.coverage = _build_coverage_report(entries, languages, state.config.review.mode)

    logger.info(
        "pipeline.pass_completed",
        pass_number=1,
        finding_count=0,
        total_files=len(entries),
        languages=languages,
    )


def path_matches_filters(rel_path: str, exclude: tuple[str, ...], include: tuple[str, ...]) -> bool:
    """True if rel_path passes the exclude/include glob filters (i.e. should be kept).

    Shared fnmatch semantics for --exclude/--include: exclude wins, then include
    (when non-empty) must match. Used by _walk_files (relative file paths) and
    by passes/sast.py's SARIF result filtering (relative finding URIs) so the
    filters apply identically whether a finding came from the LLM-facing
    manifest or a directory-scanning tool that bypasses it entirely.
    """
    import fnmatch

    if any(fnmatch.fnmatch(rel_path, pat) for pat in exclude):
        return False
    if include and not any(fnmatch.fnmatch(rel_path, pat) for pat in include):
        return False
    return True


def _walk_files(
    root: Path, max_size: int,
    exclude: tuple[str, ...] = (), include: tuple[str, ...] = (),
) -> list[Path]:
    """Walk the tree with directory pruning and optional user glob filters.

    Uses os.walk with in-place dirnames pruning instead of root.rglob("*"),
    which enumerates every entry inside excluded trees (node_modules, .git)
    before filtering them out.

    exclude: fnmatch globs on the relative POSIX path — matching files skipped,
             matching directory names pruned (never descended).
    include: when non-empty, only files whose relative path matches at least
             one glob are kept (applied after exclude).
    """
    import fnmatch
    import os

    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDE_DIRS
            and not d.endswith(".egg-info")
            and not any(fnmatch.fnmatch(f"{rel_dir}/{d}".lstrip("./"), pat) or fnmatch.fnmatch(d, pat)
                        for pat in exclude)
        ]
        for name in filenames:
            if any(p.search(name) for p in _EXCLUDE_FILE_PATTERNS):
                continue
            rel = f"{rel_dir}/{name}".lstrip("./") if rel_dir != "." else name
            if not path_matches_filters(rel, exclude, include):
                continue
            item = Path(dirpath) / name
            try:
                if item.stat().st_size > max_size:
                    continue
            except OSError as e:
                logger.debug("inventory.stat_failed", path=str(item), error=str(e))
                continue
            files.append(item)
    return files


def _compute_security_weight(file_path: Path, language: str) -> int:
    """Compute security relevance weight for a file (0-10)."""
    if language == "other":
        return 0

    weight = 1  # base weight for any in-scope file

    # Filename-based boost
    name_lower = file_path.name.lower()
    path_lower = str(file_path).lower()
    if "controller" in name_lower:
        weight += 3
    if "auth" in name_lower or "login" in name_lower or "oauth" in name_lower:
        weight += 2
    if "middleware" in name_lower:
        weight += 2
    if "startup" in name_lower or "program" in name_lower:
        weight += 1
    if "config" in name_lower or "settings" in name_lower:
        weight += 2
    if "secret" in name_lower or "credential" in name_lower or "key" in name_lower:
        weight += 3
    if ".env" in name_lower:
        weight += 3
    if "route" in name_lower or "endpoint" in name_lower or "view" in name_lower:
        weight += 2
    if "upload" in name_lower or "file_handler" in name_lower:
        weight += 2
    if "docker" in name_lower:
        weight += 1

    # Content-based boost (read first 4KB for efficiency)
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            content = f.read(4096)
        for pattern, boost in _SECURITY_WEIGHT_PATTERNS:
            if pattern.search(content):
                weight += boost
    except OSError as e:
        logger.debug("inventory.read_failed", path=str(file_path), error=str(e))

    return min(weight, 10)


# -- Semantic pass mapping (hardcoded — only 2 passes) -----------------------

_SEMANTIC_COVERAGE: dict[str, list[str]] = {
    "python": ["Holistic"],
    "csharp": ["Holistic"],
    "config": ["Config Review"],
}


def _build_coverage_report(
    entries: list[FileEntry], languages: dict[str, int], mode: str,
) -> CoverageReport:
    """Build coverage report from manifest entries and tool registry.

    `mode` gates the semantic (LLM) pass columns: holistic and config_review
    only run in "full" mode, so claiming their coverage in "sast"/"sast-triage"
    runs would misrepresent what this run actually did (WP2).
    """
    specs = load_tool_specs()

    by_type: dict[str, FileCoverage] = {}
    for lang, count in languages.items():
        sample_files = [e.path for e in entries if e.language == lang]

        # Find which deterministic tools cover this language
        det_tools: list[str] = []
        for spec in specs:
            if spec.is_available() and spec.matches_files(sample_files):
                if spec.name not in det_tools:
                    det_tools.append(spec.name)

        sem_passes = _SEMANTIC_COVERAGE.get(lang, []) if mode == "full" else []

        by_type[lang] = FileCoverage(
            file_type=lang,
            file_count=count,
            deterministic_tools=det_tools,
            semantic_passes=sem_passes,
        )

    return CoverageReport(by_type=by_type)
