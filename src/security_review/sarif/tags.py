"""CWE tag normalisation for SARIF rules.

GitHub Code Scanning reads CWE from properties.tags in the
format external/cwe/cwe-NNN.
"""
from __future__ import annotations

import re

from security_review.sarif.types import SarifDocument, SarifRule

_CWE_PATTERNS = [
    re.compile(r"CWE-(\d+)"),          # CWE-89, CWE-89: SQL Injection
    re.compile(r"external/cwe/cwe-(\d+)"),  # already normalised
    re.compile(r"^(\d+)$"),             # bare number
]


def normalise_cwe_tag(raw: str | int) -> str | None:
    """Normalise a CWE reference to external/cwe/cwe-NNN format.

    Returns None if the input cannot be parsed as a CWE reference.

    Examples:
        "CWE-89: SQL Injection" -> "external/cwe/cwe-089"
        "CWE-79" -> "external/cwe/cwe-079"
        89 -> "external/cwe/cwe-089"
        "external/cwe/cwe-089" -> "external/cwe/cwe-089"
    """
    if isinstance(raw, int):
        return f"external/cwe/cwe-{raw:03d}"

    raw_str = str(raw).strip()
    for pattern in _CWE_PATTERNS:
        match = pattern.search(raw_str)
        if match:
            cwe_num = int(match.group(1))
            return f"external/cwe/cwe-{cwe_num:03d}"

    return None


def normalise_cwe_tags(rule: SarifRule) -> list[str]:
    """Ensure rule.properties.tags contains external/cwe/cwe-NNN entries.

    Scans existing tags for CWE references in various formats and
    normalises them. Returns the updated tags list.
    """
    properties = rule.setdefault("properties", {})
    tags = properties.setdefault("tags", [])

    normalised_cwes: set[str] = set()
    non_cwe_tags: list[str] = []

    for tag in tags:
        normalised = normalise_cwe_tag(tag)
        if normalised:
            normalised_cwes.add(normalised)
        else:
            non_cwe_tags.append(tag)

    # Also check rule metadata for CWE references
    for relationship in rule.get("relationships", []):
        target = relationship.get("target", {})
        tool_component = target.get("toolComponent", {})
        if tool_component.get("name") == "CWE":
            target_id = target.get("id", "")
            normalised = normalise_cwe_tag(f"CWE-{target_id}")
            if normalised:
                normalised_cwes.add(normalised)

    updated_tags = non_cwe_tags + sorted(normalised_cwes)
    properties["tags"] = updated_tags
    return updated_tags


def extract_cwe_ids_from_sarif(sarif: SarifDocument) -> set[str]:
    """Extract all unique CWE IDs (bare numbers) from a SARIF document."""
    cwe_ids: set[str] = set()

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            tags = rule.get("properties", {}).get("tags", [])
            for tag in tags:
                if tag.startswith("external/cwe/cwe-"):
                    # external/cwe/cwe-089 -> 89
                    num = tag.split("-")[-1].lstrip("0") or "0"
                    cwe_ids.add(num)

        for result in run.get("results", []):
            for taxa_ref in result.get("taxa", []):
                tool_component = taxa_ref.get("toolComponent", {})
                if tool_component.get("name") == "CWE":
                    cwe_ids.add(taxa_ref.get("id", ""))

    return cwe_ids
