"""SAST results must use the exact Pass 1 inventory file set."""
from __future__ import annotations

from security_review.passes.sast import _filter_results_to_manifest


def _result(uri: str | None) -> dict:
    result = {"ruleId": "test-rule", "message": {"text": "test"}}
    if uri is not None:
        result["locations"] = [{
            "physicalLocation": {"artifactLocation": {"uri": uri}},
        }]
    return result


def test_filter_results_to_manifest_drops_dependency_and_generated_paths():
    sarif = {
        "runs": [{
            "results": [
                _result("src/app.py"),
                _result(".venv/lib/dependency.py"),
                _result("node_modules/package/index.js"),
                _result("var/worktrees/run/workspace/src/app.py"),
                _result(None),
            ],
        }],
    }

    dropped = _filter_results_to_manifest(sarif, {"src/app.py"})

    assert dropped == 4
    assert sarif["runs"][0]["results"] == [_result("src/app.py")]


def test_filter_results_to_manifest_respects_user_filtered_manifest():
    sarif = {
        "runs": [{
            "results": [
                _result("src/app.py"),
                _result("tests/test_app.py"),
            ],
        }],
    }

    dropped = _filter_results_to_manifest(sarif, {"src/app.py"})

    assert dropped == 1
    assert sarif["runs"][0]["results"] == [_result("src/app.py")]
