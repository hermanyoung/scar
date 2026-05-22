"""Language parser protocol and registry.

Parsers extract structural and metric information from source files.
Each parser handles one language and implements the LanguageParser protocol.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from code_analysis.models import FileResult


class LanguageParser(Protocol):
    """Protocol for language-specific source file parsers."""

    @property
    def language(self) -> str: ...

    @property
    def extensions(self) -> set[str]: ...

    def analyze_file(
        self, file_path: Path, rel_path: str, *, include_structure: bool = False,
    ) -> FileResult | None:
        """Parse a file once, extract metrics and optionally structure.

        Returns None on parse failure (SyntaxError, unreadable file).
        When include_structure=True, populates FileResult.module for
        graph construction.
        """
        ...


_REGISTRY: dict[str, type] = {}


def register_parser(cls: type) -> type:
    """Class decorator to register a parser implementation."""
    instance = cls()
    _REGISTRY[instance.language] = cls
    return cls


def get_parser(language: str) -> LanguageParser:
    """Get parser by language name.

    Raises:
        ValueError: If language is not supported or dependencies are missing.
    """
    if language not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys())) or "none"
        raise ValueError(
            f"No parser for language '{language}'. Available: {available}"
        )
    return _REGISTRY[language]()


def list_languages() -> list[str]:
    """List available parser languages."""
    return sorted(_REGISTRY.keys())


def get_parser_for_extension(ext: str) -> LanguageParser | None:
    """Get parser by file extension (e.g. '.py'). Returns None if unsupported."""
    for cls in _REGISTRY.values():
        instance = cls()
        if ext in instance.extensions:
            return instance
    return None
