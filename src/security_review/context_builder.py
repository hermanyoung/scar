"""Pre-materialize file content for LLM prompts.

All LLM context is built locally — agents never call external tools
for file I/O (P14). This module provides reusable functions for:
  - Reading files with error handling
  - Formatting code with line numbers and language tags
  - Building context windows around specific lines
  - Token-budget-aware file inclusion

Used by all LLM passes (triage, holistic, config_review).
"""
from __future__ import annotations

from pathlib import Path

import structlog

logger = structlog.get_logger()


def read_file_content(target_path: Path, file_path: str) -> str | None:
    """Read a file relative to target_path. Returns content or None on failure."""
    full_path = target_path / file_path
    try:
        return full_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("context.file_read_failed", file_path=file_path, error=str(e))
        return None


def format_context_window(content: str, line: int, radius: int = 30) -> str:
    """Extract a context window around a specific line, with line numbers.

    The target line is marked with '>>>' for easy identification.
    Returns formatted string ready for prompt inclusion.
    """
    lines = content.splitlines()
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)

    formatted = []
    for i, l in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == line else "   "
        formatted.append(f"{marker} {i:4d} | {l}")

    return "\n".join(formatted)


def format_full_file(file_path: str, content: str) -> str:
    """Format a full file with header and language-tagged code block."""
    ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
    return f"### {file_path}\n```{ext}\n{content}\n```\n"


def inline_files(
    target_path: Path,
    file_paths: list[str],
    *,
    max_tokens: int = 100_000,
    reserve_tokens: int = 30_000,
) -> tuple[str, list[str], list[str]]:
    """Read and inline multiple files with token budget.

    Returns (formatted_content, files_included, files_omitted).
    Files exceeding the token budget are truncated or omitted.
    """
    available = max_tokens - reserve_tokens
    tokens_used = 0
    sections: list[str] = []
    included: list[str] = []
    omitted: list[str] = []

    for fp in file_paths:
        content = read_file_content(target_path, fp)
        if content is None:
            sections.append(f"### {fp}\n```\n# Error: could not read file\n```\n")
            included.append(fp)
            continue

        file_tokens = len(content) // 4  # rough estimate: 1 token ~ 4 chars

        if tokens_used + file_tokens <= available:
            sections.append(format_full_file(fp, content))
            tokens_used += file_tokens
            included.append(fp)
        elif tokens_used < available:
            # Partial inclusion — truncate to fit budget
            remaining_chars = (available - tokens_used) * 4
            truncated = content[:remaining_chars]
            total_lines = content.count("\n")
            included_lines = truncated.count("\n")
            ext = fp.rsplit(".", 1)[-1] if "." in fp else ""
            sections.append(
                f"### {fp}\n```{ext}\n{truncated}\n"
                f"... TRUNCATED ({total_lines - included_lines} lines omitted)\n```\n"
            )
            tokens_used = available
            included.append(fp)
        else:
            omitted.append(fp)

    if omitted:
        sections.append(
            f"\n**Note:** {len(omitted)} file(s) omitted due to token budget: "
            + ", ".join(omitted)
        )

    logger.debug(
        "context.files_inlined",
        files_included=len(included),
        files_omitted=len(omitted),
        tokens_used=tokens_used,
        token_budget=available,
    )

    return "\n".join(sections), included, omitted
