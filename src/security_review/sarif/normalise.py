"""Normalise SARIF results from different tools into consistent fields.

SAST tools produce findings in different formats:
  - Bandit: no result.level, severity in properties.issue_severity (HIGH/MEDIUM/LOW)
  - OpenGrep: no result.level, severity in rule.defaultConfiguration.level (warning)
  - betterleaks: no result.level, no severity fields (secrets)
  - Roslyn: result.level set correctly

This module runs once during SAST merge (Pass 2) and ensures every result
has a standard SARIF `level` field (error/warning/note) so downstream
consumers (triage, priority scoring, reporting) never need tool-specific logic.

Designed for extensibility: adding a new tool means adding one entry to
_TOOL_DEFAULTS, not changing consumer code.
"""
from __future__ import annotations


# SARIF level values (internal) -> human-readable severity labels
LEVEL_ERROR = "error"       # Critical / High
LEVEL_WARNING = "warning"   # Medium
LEVEL_NOTE = "note"         # Low

# Human-readable severity labels for display (single source of truth)
SEVERITY_DISPLAY: dict[str, str] = {
    "error": "Critical",
    "warning": "Medium",
    "note": "Low",
}

# Map tool-specific severity strings to SARIF levels
_SEVERITY_TO_LEVEL: dict[str, str] = {
    # Bandit issue_severity
    "critical": LEVEL_ERROR,
    "high": LEVEL_ERROR,
    "medium": LEVEL_WARNING,
    "low": LEVEL_NOTE,
    "informational": LEVEL_NOTE,
    # SARIF levels (passthrough)
    "error": LEVEL_ERROR,
    "warning": LEVEL_WARNING,
    "note": LEVEL_NOTE,
    "none": LEVEL_NOTE,
}

# Default level per tool when no severity info is available
_TOOL_DEFAULTS: dict[str, str] = {
    "bandit": LEVEL_WARNING,
    "opengrep": LEVEL_WARNING,
    "betterleaks": LEVEL_WARNING,    # Secrets are at least medium
    "gitleaks": LEVEL_WARNING,
    "pip-audit": LEVEL_WARNING,
    "dotnet-vuln": LEVEL_WARNING,
    "roslyn": LEVEL_NOTE,
}


def normalise_sarif_levels(sarif: dict) -> None:
    """Ensure every result has a standard SARIF `level` field.

    Resolution order per result:
    1. result.level (if already a valid SARIF level)
    2. result.properties.issue_severity (Bandit format)
    3. Matching rule.defaultConfiguration.level (OpenGrep format)
    4. Tool-specific default from _TOOL_DEFAULTS
    5. Final fallback: "warning"

    Mutates the SARIF dict in place.
    """
    for run in sarif.get("runs", []):
        tool_name = (
            run.get("tool", {}).get("driver", {}).get("name", "unknown").lower()
        )

        # Build rule lookup: ruleId -> defaultConfiguration.level
        rule_levels: dict[str, str] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_id = rule.get("id", "")
            default_level = rule.get("defaultConfiguration", {}).get("level")
            if default_level:
                rule_levels[rule_id] = default_level.lower()

        tool_default = _TOOL_DEFAULTS.get(tool_name, LEVEL_WARNING)

        for result in run.get("results", []):
            level = _resolve_level(result, rule_levels, tool_default)
            result["level"] = level


def _resolve_level(
    result: dict,
    rule_levels: dict[str, str],
    tool_default: str,
) -> str:
    """Resolve the SARIF level for a single result."""
    # 1. Existing result.level
    existing = result.get("level", "").lower()
    if existing in _SEVERITY_TO_LEVEL:
        return _SEVERITY_TO_LEVEL[existing]

    # 2. properties.issue_severity (Bandit)
    issue_sev = result.get("properties", {}).get("issue_severity", "").lower()
    if issue_sev and issue_sev in _SEVERITY_TO_LEVEL:
        return _SEVERITY_TO_LEVEL[issue_sev]

    # 3. Rule defaultConfiguration.level (OpenGrep)
    rule_id = result.get("ruleId", "")
    rule_level = rule_levels.get(rule_id, "").lower()
    if rule_level and rule_level in _SEVERITY_TO_LEVEL:
        return _SEVERITY_TO_LEVEL[rule_level]

    # 4. Tool default
    return tool_default
