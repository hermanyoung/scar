"""Tests for SARIF merger: dedup, highest severity wins."""
from __future__ import annotations

from security_review.sarif.merger import merge_sarif


def test_merge_empty():
    result = merge_sarif([])
    assert result["version"] == "2.1.0"
    assert len(result["runs"]) == 1
    assert len(result["runs"][0]["results"]) == 0


def test_merge_single_one_run():
    """Single doc with one run is returned as-is (identity)."""
    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tool-a", "rules": []}},
            "results": [{"ruleId": "A001", "level": "warning", "message": {"text": "f1"}}],
        }],
    }
    result = merge_sarif([doc])
    assert result is doc


def test_merge_single_multi_run_consolidates(sample_sarif):
    """Single doc with multiple runs gets consolidated into one run."""
    result = merge_sarif([sample_sarif])
    assert len(result["runs"]) == 1
    assert len(result["runs"][0]["results"]) == 3


def test_merge_dedup_highest_severity():
    """S-04: same (file, line, CWE) from two tools keeps highest severity."""
    doc1 = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tool-a", "rules": []}},
            "results": [{
                "ruleId": "A001",
                "level": "warning",
                "message": {"text": "Finding from tool A"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 10},
                    }
                }],
                "properties": {"tags": ["external/cwe/cwe-089"]},
            }],
        }],
    }
    doc2 = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tool-b", "rules": []}},
            "results": [{
                "ruleId": "B001",
                "level": "error",
                "message": {"text": "Finding from tool B"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 10},
                    }
                }],
                "properties": {"tags": ["external/cwe/cwe-089"]},
            }],
        }],
    }

    result = merge_sarif([doc1, doc2])
    results = result["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"  # highest severity wins


def test_merge_preserves_distinct_findings():
    doc1 = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tool-a", "rules": []}},
            "results": [{
                "ruleId": "A001",
                "level": "warning",
                "message": {"text": "Finding 1"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 10},
                    }
                }],
            }],
        }],
    }
    doc2 = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tool-b", "rules": []}},
            "results": [{
                "ruleId": "B001",
                "level": "warning",
                "message": {"text": "Finding 2"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "models.py"},
                        "region": {"startLine": 20},
                    }
                }],
            }],
        }],
    }

    result = merge_sarif([doc1, doc2])
    results = result["runs"][0]["results"]
    assert len(results) == 2
