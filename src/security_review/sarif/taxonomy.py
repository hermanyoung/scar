"""CWE taxonomy injection into SARIF documents."""
from __future__ import annotations

import yaml

from security_review import MODULE_ROOT
from security_review.errors import ConfigurationError
from security_review.sarif.types import SarifDocument, SarifTaxonomy


def load_cwe_registry() -> dict[str, dict]:
    """Load the canonical CWE registry from config/taxonomy/cwe.yaml.

    Returns dict mapping CWE ID string (e.g. "89") to entry with 'name' field.
    """
    cwe_path = MODULE_ROOT / "config" / "taxonomy" / "cwe.yaml"
    if not cwe_path.exists():
        raise ConfigurationError(
            f"CWE taxonomy not found: {cwe_path}",
            code="SYS_CWE_NOT_FOUND",
        )

    with open(cwe_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"CWE taxonomy is not a YAML mapping: {cwe_path}",
            code="SYS_CWE_NOT_FOUND",
        )

    return data


def build_cwe_taxonomy(used_cwes: set[str]) -> SarifTaxonomy:
    """Build a SARIF taxonomies entry for the CWEs referenced in results.

    Args:
        used_cwes: Set of CWE IDs (e.g. {"89", "79", "502"})

    Returns:
        SARIF toolComponent dict for the CWE taxonomy.
    """
    registry = load_cwe_registry()
    return {
        "name": "CWE",
        "version": "4.16",
        "informationUri": "https://cwe.mitre.org/data/published/cwe_v4.16.pdf",
        "organization": "MITRE",
        "isComprehensive": False,
        "taxa": [
            {
                "id": str(cwe_id),
                "name": registry[cwe_id]["name"],
                "shortDescription": {"text": registry[cwe_id]["name"]},
            }
            for cwe_id in sorted(used_cwes)
            if cwe_id in registry
        ],
    }


def inject_taxonomy(sarif: SarifDocument, used_cwes: set[str]) -> SarifDocument:
    """Add CWE taxonomy to a SARIF document's runs."""
    taxonomy = build_cwe_taxonomy(used_cwes)

    for run in sarif.get("runs", []):
        taxonomies = run.setdefault("taxonomies", [])
        # Remove existing CWE taxonomy if present
        taxonomies[:] = [t for t in taxonomies if t.get("name") != "CWE"]
        taxonomies.append(taxonomy)

    return sarif
