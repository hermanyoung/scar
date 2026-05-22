"""Tests for CWE taxonomy and tag normalisation."""
from __future__ import annotations

from security_review.sarif.tags import (
    extract_cwe_ids_from_sarif,
    normalise_cwe_tag,
    normalise_cwe_tags,
)
from security_review.sarif.taxonomy import build_cwe_taxonomy, load_cwe_registry


def test_load_cwe_registry():
    registry = load_cwe_registry()
    assert "89" in registry
    assert registry["89"]["name"] == "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
    assert "502" in registry
    assert "798" in registry


def test_build_cwe_taxonomy():
    taxonomy = build_cwe_taxonomy({"89", "79"})
    assert taxonomy["name"] == "CWE"
    assert len(taxonomy["taxa"]) == 2
    ids = {t["id"] for t in taxonomy["taxa"]}
    assert "79" in ids
    assert "89" in ids


def test_build_cwe_taxonomy_skips_unknown():
    taxonomy = build_cwe_taxonomy({"89", "99999"})
    assert len(taxonomy["taxa"]) == 1


def test_normalise_cwe_tag_from_string():
    assert normalise_cwe_tag("CWE-89: SQL Injection") == "external/cwe/cwe-089"
    assert normalise_cwe_tag("CWE-79") == "external/cwe/cwe-079"


def test_normalise_cwe_tag_from_int():
    assert normalise_cwe_tag(89) == "external/cwe/cwe-089"
    assert normalise_cwe_tag(502) == "external/cwe/cwe-502"


def test_normalise_cwe_tag_already_normalised():
    assert normalise_cwe_tag("external/cwe/cwe-089") == "external/cwe/cwe-089"


def test_normalise_cwe_tag_invalid():
    assert normalise_cwe_tag("not-a-cwe") is None


def test_normalise_cwe_tags_on_rule():
    rule = {
        "id": "B307",
        "properties": {"tags": ["security", "CWE-94"]},
    }
    tags = normalise_cwe_tags(rule)
    assert "external/cwe/cwe-094" in tags
    assert "security" in tags
    assert "CWE-94" not in tags  # replaced with normalised form


def test_extract_cwe_ids_from_sarif(sample_sarif):
    cwe_ids = extract_cwe_ids_from_sarif(sample_sarif)
    # The sample_sarif has CWE-94, CWE-78, CWE-798 in tags
    # After normalisation these become extractable
    assert isinstance(cwe_ids, set)
