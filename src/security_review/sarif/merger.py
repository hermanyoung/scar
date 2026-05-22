"""Merge multiple SARIF documents with deduplication."""
from __future__ import annotations

from security_review import __version__
from security_review.models.findings import Severity
from security_review.sarif.loader import get_finding_key
from security_review.sarif.types import SarifDocument

_SEVERITY_ORDER = {
    "error": 4,
    "warning": 3,
    "note": 2,
    "none": 1,
}


def merge_sarif(documents: list[SarifDocument]) -> SarifDocument:
    """Merge multiple SARIF documents into a single document.

    Deduplicates results by (cwe_id, file_path, line_number).
    When duplicates exist, the finding with the highest severity wins.
    Rules from all runs are merged into a single driver.
    """
    if not documents:
        return _empty_sarif()

    if len(documents) == 1 and len(documents[0].get("runs", [])) <= 1:
        return documents[0]

    merged_rules: dict[str, dict] = {}
    seen_results: dict[tuple, dict] = {}
    tool_names: list[str] = []

    for doc in documents:
        for run in doc.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            tool_name = driver.get("name", "unknown")
            tool_names.append(tool_name)

            # Collect rules
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                if rule_id not in merged_rules:
                    merged_rules[rule_id] = rule

            # Collect results with dedup
            for result in run.get("results", []):
                key = get_finding_key(result)
                existing = seen_results.get(key)

                if existing is None:
                    result_copy = dict(result)
                    result_copy.setdefault("properties", {})["tool_name"] = tool_name
                    seen_results[key] = result_copy
                else:
                    # Keep highest severity
                    new_sev = _severity_rank(result.get("level", "none"))
                    old_sev = _severity_rank(existing.get("level", "none"))
                    if new_sev > old_sev:
                        result_copy = dict(result)
                        result_copy.setdefault("properties", {})["tool_name"] = tool_name
                        seen_results[key] = result_copy

    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scar",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": list(merged_rules.values()),
                    }
                },
                "results": list(seen_results.values()),
            }
        ],
    }


def _severity_rank(level: str) -> int:
    return _SEVERITY_ORDER.get(level.lower(), 0)


def _empty_sarif() -> SarifDocument:
    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scar",
                        "version": __version__,
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }
