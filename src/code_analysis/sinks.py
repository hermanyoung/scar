"""Classify methods as sinks or entry points.

Sink patterns match two ways:
  1. classify_symbol() tags a locally-defined method/function as is_sink=True
     when its OWN qualified_name matches a pattern (custom wrapper methods,
     e.g. a project's own `def execute(self, sql): ...` helper).
  2. sink_patterns_for_cwe() exposes the same patterns for walk.py to match
     directly against call-edge *callee* names -- the primary mechanism,
     since real-world sinks (cursor.execute, os.system, pickle.loads) are
     external library calls that never appear in the target's own parsed
     symbol table and so can never be tagged by (1) alone.
"""

from __future__ import annotations

from fnmatch import fnmatch
from functools import lru_cache

import yaml

from code_analysis import MODULE_ROOT
from code_analysis.models import SymbolInfo


@lru_cache
def _load_sinks_config() -> dict:
    config_path = MODULE_ROOT / "config" / "taxonomy" / "sinks.yaml"
    if not config_path.exists():
        raise FileNotFoundError(f"Sink patterns not found: {config_path}")
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def sink_patterns_for_cwe(cwe_id: str) -> list[str]:
    """Return all sink patterns tagged with this CWE, across every language.

    CWE keys in sinks.yaml use the "CWE-NNN" form; cwe_id may be passed as
    "89" or "CWE-89" -- both are normalised before lookup.
    """
    normalised = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
    config = _load_sinks_config()
    patterns: list[str] = []
    for lang_config in config.values():
        patterns.extend(lang_config.get("sinks", {}).get(normalised, []))
    return patterns


def matches_any_sink_pattern(callee: str, cwe_id: str) -> bool:
    """True if callee matches any sink pattern registered for cwe_id."""
    return any(fnmatch(callee, pattern) for pattern in sink_patterns_for_cwe(cwe_id))


def classify_symbol(symbol: SymbolInfo, language: str) -> None:
    """Mutate symbol in place: set is_sink, is_entry_point, cwe_tags.

    Matches the symbol's qualified_name against sink patterns from sinks.yaml.
    Matches decorators (and, for C#, base classes) against entry-point patterns.
    """
    config = _load_sinks_config()
    lang_config = config.get(language, {})

    for cwe_id, patterns in lang_config.get("sinks", {}).items():
        for pattern in patterns:
            if fnmatch(symbol.qualified_name, pattern) or fnmatch(symbol.name, pattern.split(".")[-1]):
                symbol.is_sink = True
                if cwe_id not in symbol.cwe_tags:
                    symbol.cwe_tags.append(cwe_id)

    ep_config = lang_config.get("entry_points", {})
    if isinstance(ep_config, list):
        # Python: list of decorator patterns
        for dec in symbol.decorators:
            for pattern in ep_config:
                if fnmatch(dec, pattern):
                    symbol.is_entry_point = True
                    break
    elif isinstance(ep_config, dict):
        # C#: decorators + base_classes
        decorator_patterns = ep_config.get("decorators", [])
        base_patterns = ep_config.get("base_classes", [])
        for dec in symbol.decorators:
            if dec in decorator_patterns:
                symbol.is_entry_point = True
                break
        for base in symbol.bases:
            if base in base_patterns or any(base.endswith(f".{bp}") for bp in base_patterns):
                symbol.is_entry_point = True
                break
