"""Convert non-SARIF tool output (JSON/JSONL) to SARIF 2.1.0."""
from __future__ import annotations

import json
from pathlib import Path

from security_review.errors import ConfigurationError, SARIFError
from security_review.sarif.types import SarifDocument

_DEPENDENCY_CWE = "1395"


def _dependency_cwe_tag() -> str:
    """The CWE tag for third-party-dependency findings, validated against the taxonomy."""
    from security_review.sarif.taxonomy import cwe_exists
    if not cwe_exists(_DEPENDENCY_CWE):
        raise ConfigurationError(
            f"CWE-{_DEPENDENCY_CWE} is not in config/taxonomy/cwe.yaml — "
            f"add it before converting dependency-scanner output.",
            code="SYS_CWE_NOT_FOUND",
        )
    return f"external/cwe/cwe-{_DEPENDENCY_CWE}"


def convert_pip_audit_to_sarif(json_path: Path | str) -> SarifDocument:
    """Convert pip-audit JSON output to SARIF 2.1.0.

    pip-audit JSON format:
    {
      "dependencies": [
        {
          "name": "package",
          "version": "1.0",
          "vulns": [
            {"id": "PYSEC-...", "fix_versions": ["1.1"], "description": "..."}
          ]
        }
      ]
    }
    """
    path = Path(json_path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise SARIFError(
            f"Failed to convert pip-audit output from {path}: {e}",
            code="SARIF_CONVERT_FAILED",
        ) from e

    results = []
    rules: dict[str, dict] = {}

    for dep in data.get("dependencies", []):
        pkg_name = dep.get("name", "unknown")
        pkg_version = dep.get("version", "unknown")
        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id", "UNKNOWN")
            description = vuln.get("description", "")
            fix_versions = vuln.get("fix_versions", [])
            fix_str = f" Fix: upgrade to {', '.join(fix_versions)}" if fix_versions else ""

            rule_id = f"SCA-{vuln_id}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f"Vulnerable dependency: {pkg_name}"},
                    "properties": {"tags": ["security", "sca", _dependency_cwe_tag()]},
                }

            results.append({
                "ruleId": rule_id,
                "level": "warning",
                "message": {
                    "text": f"{pkg_name}=={pkg_version} has known vulnerability {vuln_id}.{fix_str}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(path.name)},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            })

    return _wrap_sarif("pip-audit", rules, results)


def convert_dotnet_vuln_to_sarif(json_path: Path | str) -> SarifDocument:
    """Convert `dotnet list package --vulnerable --format json` output to SARIF 2.1.0.

    dotnet JSON format:
    {
      "projects": [
        {
          "path": "...",
          "frameworks": [
            {
              "framework": "net8.0",
              "topLevelPackages": [
                {
                  "id": "Package",
                  "requestedVersion": "1.0",
                  "resolvedVersion": "1.0",
                  "vulnerabilities": [
                    {"severity": "High", "advisoryurl": "https://..."}
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
    """
    path = Path(json_path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise SARIFError(
            f"Failed to convert dotnet vulnerability output from {path}: {e}",
            code="SARIF_CONVERT_FAILED",
        ) from e

    results = []
    rules: dict[str, dict] = {}

    for project in data.get("projects", []):
        project_path = project.get("path", "unknown.csproj")
        for framework in project.get("frameworks", []):
            for pkg_list_key in ("topLevelPackages", "transitivePackages"):
                for pkg in framework.get(pkg_list_key, []):
                    pkg_id = pkg.get("id", "unknown")
                    resolved = pkg.get("resolvedVersion", "unknown")
                    for vuln in pkg.get("vulnerabilities", []):
                        severity = vuln.get("severity", "Unknown")
                        advisory_url = vuln.get("advisoryurl", "")
                        level = _dotnet_severity_to_sarif(severity)

                        rule_id = f"SCA-NUGET-{pkg_id}"
                        if rule_id not in rules:
                            rules[rule_id] = {
                                "id": rule_id,
                                "shortDescription": {"text": f"Vulnerable NuGet package: {pkg_id}"},
                                "helpUri": advisory_url,
                                "properties": {"tags": ["security", "sca", _dependency_cwe_tag()]},
                            }

                        results.append({
                            "ruleId": rule_id,
                            "level": level,
                            "message": {
                                "text": f"{pkg_id}@{resolved} has a {severity} vulnerability. See {advisory_url}"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": project_path},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        })

    return _wrap_sarif("dotnet-vuln", rules, results)


def convert_sarif_v1_to_v2(path: Path | str) -> SarifDocument:
    """Convert SARIF 1.0.0 (Roslyn output) to SARIF 2.1.0.

    Key differences:
      v1 tool.name            -> v2 tool.driver.name
      v1 location.resultFile  -> v2 location.physicalLocation.artifactLocation
      v1 properties.tags      -> preserved as-is
    """
    path = Path(path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        raise SARIFError(
            f"Failed to convert SARIF v1 from {path}: {e}",
            code="SARIF_CONVERT_FAILED",
        ) from e

    v1_runs = data.get("runs", [])
    if not v1_runs:
        return _wrap_sarif("roslyn", {}, [])

    v1_run = v1_runs[0]
    v1_tool = v1_run.get("tool", {})
    tool_name = v1_tool.get("name", "roslyn")
    tool_version = v1_tool.get("version", "unknown")

    results = []
    rules: dict[str, dict] = {}

    for v1_result in v1_run.get("results", []):
        rule_id = v1_result.get("ruleId", "")
        level = v1_result.get("level", "warning")
        message = v1_result.get("message", "")

        # Convert v1 locations (resultFile) to v2 (physicalLocation)
        v2_locations = []
        for v1_loc in v1_result.get("locations", []):
            result_file = v1_loc.get("resultFile", {})
            if result_file:
                v2_locations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": result_file.get("uri", "")},
                        "region": result_file.get("region", {}),
                    }
                })

        # Collect rules
        if rule_id and rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": rule_id},
                "properties": {"tags": ["security"]},
            }

        v2_result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": v2_locations,
        }

        # Preserve any v1 properties
        if "properties" in v1_result:
            v2_result["properties"] = v1_result["properties"]

        results.append(v2_result)

    sarif = _wrap_sarif(tool_name, rules, results)
    sarif["runs"][0]["tool"]["driver"]["version"] = tool_version
    return sarif


def _wrap_sarif(tool_name: str, rules: dict[str, dict], results: list[dict]) -> SarifDocument:
    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _dotnet_severity_to_sarif(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "moderate": "warning",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(severity.lower(), "warning")
