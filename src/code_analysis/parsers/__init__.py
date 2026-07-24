"""Language parser protocol and registry.

Parsers extract structural and metric information from source files.
Each parser handles one language and implements the LanguageParser protocol.

Implementation lives in registry.py (plan 021 WP-H, rule 001.3: no logic
in __init__.py) — this module re-exports the public API only.
"""

from __future__ import annotations

from code_analysis.parsers.registry import (
    LanguageParser,
    get_parser,
    get_parser_for_extension,
    list_languages,
    register_parser,
)

__all__ = [
    "LanguageParser",
    "get_parser",
    "get_parser_for_extension",
    "list_languages",
    "register_parser",
]
