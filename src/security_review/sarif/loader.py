"""Load and normalise SARIF 2.1.0 documents."""
from __future__ import annotations

import json
from pathlib import Path

from security_review.errors import SARIFError
from security_review.sarif.types import SarifDocument, SarifResult, SarifRun

SARIF_SCHEMA_VERSION = "2.1.0"


def load_sarif(path: Path | str) -> SarifDocument:
    """Load a SARIF file and validate basic structure.

    Returns the parsed SARIF dict. Raises SARIFError if the file
    cannot be parsed or lacks required SARIF 2.1.0 structure.
    """
    path = Path(path)
    if not path.exists():
        raise SARIFError(
            f"SARIF file not found: {path}",
            code="SARIF_PARSE_FAILED",
        )

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        raise SARIFError(
            f"Failed to parse SARIF from {path}: {e}",
            code="SARIF_PARSE_FAILED",
        ) from e

    _validate_sarif_structure(data, path)
    return data


def load_sarif_from_string(content: str, source: str = "<string>") -> SarifDocument:
    """Parse SARIF from a JSON string."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise SARIFError(
            f"Failed to parse SARIF from {source}: {e}",
            code="SARIF_PARSE_FAILED",
        ) from e

    _validate_sarif_structure(data, source)
    return data


def _validate_sarif_structure(data: dict, source: Path | str) -> None:
    if not isinstance(data, dict):
        raise SARIFError(
            f"SARIF from {source} is not a JSON object",
            code="SARIF_PARSE_FAILED",
        )

    version = data.get("version")
    if version != SARIF_SCHEMA_VERSION:
        raise SARIFError(
            f"SARIF from {source} has version '{version}', expected '{SARIF_SCHEMA_VERSION}'",
            code="SARIF_PARSE_FAILED",
        )

    if "runs" not in data or not isinstance(data["runs"], list):
        raise SARIFError(
            f"SARIF from {source} missing 'runs' array",
            code="SARIF_PARSE_FAILED",
        )


def extract_findings(sarif: SarifDocument) -> list[SarifResult]:
    """Extract all results from a SARIF document into a flat list.

    Each result dict is augmented with properties["tool_name"] from the parent
    run's tool.driver.name field.
    """
    findings = []
    for run in sarif.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        for result in run.get("results", []):
            result_copy = dict(result)
            result_copy.setdefault("properties", {})["tool_name"] = tool_name
            findings.append(result_copy)
    return findings


def get_finding_key(result: SarifResult) -> tuple[str, str, int]:
    """Extract dedup key (cwe_id, file_path, line_number) from a SARIF result."""
    cwe_id = _extract_cwe_from_result(result)
    file_path = ""
    line_number = 0

    locations = result.get("locations", [])
    if locations:
        phys = locations[0].get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        file_path = artifact.get("uri", "")
        region = phys.get("region", {})
        line_number = region.get("startLine", 0)

    return (cwe_id, file_path, line_number)


def _extract_cwe_from_result(result: SarifResult) -> str:
    """Extract CWE ID from a SARIF result's taxa or tags."""
    # Check taxa references
    for taxa_ref in result.get("taxa", []):
        tool_component = taxa_ref.get("toolComponent", {})
        if tool_component.get("name") == "CWE":
            return taxa_ref.get("id", "")

    # Check rule properties tags
    rule_id = result.get("ruleId", "")
    properties = result.get("properties", {})
    for tag in properties.get("tags", []):
        if tag.startswith("external/cwe/cwe-"):
            # external/cwe/cwe-089 -> 89
            return tag.split("-")[-1].lstrip("0") or "0"

    return rule_id


def normalize_uri(uri: str, target_root: str | None = None) -> str:
    """Normalize a SARIF artifact URI to a consistent relative path.

    Handles all formats produced by different SAST tools:
      file:///absolute/path/file.py  -> relative/path/file.py
      /absolute/path/file.py         -> relative/path/file.py
      relative/path/file.py          -> relative/path/file.py

    If target_root is provided, strips it to produce a relative path.
    """
    # Strip file:// scheme
    if uri.startswith("file://"):
        uri = uri[7:]

    # Strip target root prefix to get relative path
    if target_root:
        prefix = target_root.rstrip("/") + "/"
        if uri.startswith(prefix):
            uri = uri[len(prefix):]

    return uri


def get_result_location(result: SarifResult, target_root: str | None = None) -> tuple[str, int]:
    """Extract (file_path, line_number) from a SARIF result's first location.

    Normalizes URIs to relative paths when target_root is provided.
    """
    locations = result.get("locations", [])
    if not locations:
        return ("", 0)
    phys = locations[0].get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri", "")
    line = phys.get("region", {}).get("startLine", 0)

    return (normalize_uri(uri, target_root), line)


def get_tool_name(run: SarifRun) -> str:
    """Extract tool name from a SARIF run."""
    return run.get("tool", {}).get("driver", {}).get("name", "unknown")


def get_findings_for_file(
    sarif: SarifDocument, file_path: str, target_root: str | None = None,
) -> list[dict]:
    """Get all findings for a specific file from a SARIF document.

    Returns list of dicts with: rule_id, tool_name, line_number, severity, message.
    """
    findings = []
    for run in sarif.get("runs", []):
        tool_name = get_tool_name(run)
        for result in run.get("results", []):
            uri, line = get_result_location(result, target_root=target_root)
            if uri == file_path:
                findings.append({
                    "rule_id": result.get("ruleId", ""),
                    "tool_name": tool_name,
                    "line_number": line,
                    "severity": result.get("level", "warning"),
                    "message": result.get("message", {}).get("text", ""),
                })
    return findings
