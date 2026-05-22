"""Unit tests for the evaluation harness.

Covers: .bench file parsing, baseline manifest loading, evaluation logic,
metrics computation. No LLM calls — uses mock findings.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from security_review.evaluation import (
    BaselineCWE,
    BaselineExpectedFinding,
    BaselineManifest,
    BenchSpec,
    EvaluationSummary,
    BenchResult,
    compute_metrics,
    discover_bench_files,
    evaluate_baseline_cwe,
    evaluate_eval_result,
    load_baseline_manifest,
    _check_evidence,
    _severity_meets_minimum,
)


# ---------------------------------------------------------------------------
# BenchSpec parsing
# ---------------------------------------------------------------------------


class TestBenchSpecParsing:
    def test_minimal_found(self):
        spec = BenchSpec.model_validate({"cwe": "863", "expect": "found"})
        assert spec.cwe == "863"
        assert spec.expect == "found"
        assert spec.severity is None
        assert spec.evidence_contains == []

    def test_full_found(self):
        spec = BenchSpec.model_validate({
            "cwe": "200",
            "expect": "found",
            "severity": "HIGH",
            "evidence_contains": ["ConnectionString", "MachineName"],
            "notes": "test note",
        })
        assert spec.severity == "HIGH"
        assert len(spec.evidence_contains) == 2

    def test_not_found(self):
        spec = BenchSpec.model_validate({"cwe": "863", "expect": "not_found"})
        assert spec.expect == "not_found"

    def test_invalid_expect_rejected(self):
        with pytest.raises(Exception):
            BenchSpec.model_validate({"cwe": "863", "expect": "maybe"})

    def test_extra_fields_rejected(self):
        with pytest.raises(Exception):
            BenchSpec.model_validate({
                "cwe": "863", "expect": "found", "unknown_field": True,
            })

    def test_missing_cwe_rejected(self):
        with pytest.raises(Exception):
            BenchSpec.model_validate({"expect": "found"})


# ---------------------------------------------------------------------------
# BaselineManifest parsing
# ---------------------------------------------------------------------------


class TestBaselineManifestParsing:
    def test_valid_manifest(self):
        data = {
            "target": "example-target",
            "cwes": [
                {
                    "cwe": "863",
                    "min_findings": 2,
                    "expected": [
                        {"file": "Controllers/ContactsController.cs", "evidence_contains": ["DeleteContact"]},
                    ],
                },
                {
                    "cwe": "200",
                    "min_findings": 3,
                    "expected": [],
                },
            ],
        }
        manifest = BaselineManifest.model_validate(data)
        assert manifest.target == "example-target"
        assert len(manifest.cwes) == 2
        assert manifest.cwes[0].min_findings == 2
        assert manifest.cwes[0].expected[0].file == "Controllers/ContactsController.cs"

    def test_empty_cwes_rejected(self):
        with pytest.raises(Exception):
            BaselineManifest.model_validate({"target": "test", "cwes": []})

    def test_extra_fields_rejected(self):
        with pytest.raises(Exception):
            BaselineManifest.model_validate({
                "target": "test",
                "cwes": [{"cwe": "863"}],
                "extra": True,
            })


# ---------------------------------------------------------------------------
# .bench file discovery
# ---------------------------------------------------------------------------


class TestBenchDiscovery:
    def test_discovers_bench_files(self, tmp_path: Path):
        # Create test .bench files
        d = tmp_path / "idor"
        d.mkdir()
        (d / "vuln.cs").write_text("// vulnerable code")
        (d / "vuln.cs.bench").write_text(yaml.dump({"cwe": "863", "expect": "found"}))
        (d / "safe.cs").write_text("// safe code")
        (d / "safe.cs.bench").write_text(yaml.dump({"cwe": "863", "expect": "not_found"}))

        results = discover_bench_files(tmp_path)
        assert len(results) == 2
        cwes = {spec.cwe for _, spec in results}
        assert cwes == {"863"}

    def test_cwe_filter(self, tmp_path: Path):
        d = tmp_path / "tests"
        d.mkdir()
        (d / "a.cs").write_text("code")
        (d / "a.cs.bench").write_text(yaml.dump({"cwe": "863", "expect": "found"}))
        (d / "b.cs").write_text("code")
        (d / "b.cs.bench").write_text(yaml.dump({"cwe": "200", "expect": "found"}))

        results = discover_bench_files(tmp_path, cwe_filter={"863"})
        assert len(results) == 1
        assert results[0][1].cwe == "863"

    def test_skips_invalid_bench(self, tmp_path: Path):
        d = tmp_path / "bad"
        d.mkdir()
        (d / "broken.cs").write_text("code")
        (d / "broken.cs.bench").write_text("not: valid: yaml: [")

        results = discover_bench_files(tmp_path)
        assert len(results) == 0

    def test_empty_eval_dir(self, tmp_path: Path):
        results = discover_bench_files(tmp_path)
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Baseline manifest file loading
# ---------------------------------------------------------------------------


class TestBaselineLoading:
    def test_load_from_file(self, tmp_path: Path):
        data = {
            "target": "my-app",
            "cwes": [{"cwe": "863", "min_findings": 1}],
        }
        f = tmp_path / "baseline.yaml"
        f.write_text(yaml.dump(data))

        manifest = load_baseline_manifest(f)
        assert manifest.target == "my-app"
        assert len(manifest.cwes) == 1


# ---------------------------------------------------------------------------
# Evaluation: eval tests
# ---------------------------------------------------------------------------


def _mock_finding(*, evidence="", description="", title="", severity="HIGH", file_path="test.cs"):
    """Create a mock HolisticFinding-like object."""
    f = MagicMock()
    f.evidence = evidence
    f.description = description
    f.title = title
    f.severity = MagicMock()
    f.severity.value = severity
    f.file_path = file_path
    return f


class TestEvalResults:
    def test_found_with_findings_passes(self):
        spec = BenchSpec(cwe="863", expect="found")
        findings = [_mock_finding(evidence="DeleteContact called")]
        result = evaluate_eval_result(spec, findings, 1.0, "test.bench")
        assert result.status == "PASS"
        assert result.finding_count == 1

    def test_found_no_findings_fails(self):
        spec = BenchSpec(cwe="863", expect="found")
        result = evaluate_eval_result(spec, [], 1.0, "test.bench")
        assert result.status == "FAIL"

    def test_not_found_no_findings_passes(self):
        spec = BenchSpec(cwe="863", expect="not_found")
        result = evaluate_eval_result(spec, [], 1.0, "test.bench")
        assert result.status == "PASS"

    def test_not_found_with_findings_is_fp(self):
        spec = BenchSpec(cwe="863", expect="not_found")
        findings = [_mock_finding()]
        result = evaluate_eval_result(spec, findings, 1.0, "test.bench")
        assert result.status == "FP"

    def test_evidence_keyword_matching(self):
        spec = BenchSpec(cwe="863", expect="found", evidence_contains=["DeleteContact"])
        findings = [_mock_finding(evidence="void DeleteContact(string id)")]
        result = evaluate_eval_result(spec, findings, 1.0, "test.bench")
        assert result.status == "PASS"
        assert result.evidence_matched is True

    def test_evidence_keyword_not_matched_fails(self):
        spec = BenchSpec(cwe="863", expect="found", evidence_contains=["DeleteContact"])
        findings = [_mock_finding(evidence="something else entirely")]
        result = evaluate_eval_result(spec, findings, 1.0, "test.bench")
        assert result.status == "FAIL"
        assert result.evidence_matched is False

    def test_multiple_evidence_keywords_all_must_match(self):
        spec = BenchSpec(cwe="863", expect="found",
                         evidence_contains=["DeleteContact", "UpdateContact"])
        findings = [
            _mock_finding(evidence="DeleteContact"),
            _mock_finding(evidence="UpdateContact"),
        ]
        result = evaluate_eval_result(spec, findings, 1.0, "test.bench")
        assert result.status == "PASS"

    def test_severity_check_meets_minimum(self):
        spec = BenchSpec(cwe="863", expect="found", severity="HIGH")
        findings = [_mock_finding(severity="CRITICAL")]
        result = evaluate_eval_result(spec, findings, 1.0, "test.bench")
        assert result.status == "PASS"

    def test_severity_check_below_minimum_still_passes_if_found(self):
        """Severity check is not currently a hard gate — finding existence matters most."""
        spec = BenchSpec(cwe="863", expect="found", severity="HIGH")
        findings = [_mock_finding(severity="MEDIUM")]
        result = evaluate_eval_result(spec, findings, 1.0, "test.bench")
        # Finding was found — PASS (severity is informational, not a gate)
        assert result.status == "PASS"


# ---------------------------------------------------------------------------
# Evaluation: baseline/application tests
# ---------------------------------------------------------------------------


class TestBaselineEvaluation:
    def test_meets_minimum(self):
        bl = BaselineCWE(cwe="863", min_findings=2)
        findings = [_mock_finding(), _mock_finding()]
        passed, _ = evaluate_baseline_cwe(bl, findings)
        assert passed is True

    def test_below_minimum(self):
        bl = BaselineCWE(cwe="863", min_findings=3)
        findings = [_mock_finding()]
        passed, detail = evaluate_baseline_cwe(bl, findings)
        assert passed is False
        assert "expected 3+" in detail

    def test_expected_file_present(self):
        bl = BaselineCWE(
            cwe="863", min_findings=1,
            expected=[BaselineExpectedFinding(
                file="Controllers/ContactsController.cs",
                evidence_contains=["DeleteContact"],
            )],
        )
        findings = [_mock_finding(
            file_path="Controllers/ContactsController.cs",
            evidence="DeleteContact method",
        )]
        passed, _ = evaluate_baseline_cwe(bl, findings)
        assert passed is True

    def test_expected_file_missing(self):
        bl = BaselineCWE(
            cwe="863", min_findings=1,
            expected=[BaselineExpectedFinding(file="WrongFile.cs")],
        )
        findings = [_mock_finding(file_path="OtherFile.cs")]
        passed, detail = evaluate_baseline_cwe(bl, findings)
        assert passed is False
        assert "WrongFile.cs" in detail


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_all_pass(self):
        results = [
            BenchResult(bench_file="a", cwe="863", expect="found", status="PASS", finding_count=2),
            BenchResult(bench_file="b", cwe="863", expect="not_found", status="PASS", finding_count=0),
        ]
        summary = compute_metrics(results, "test-provider")
        assert summary.passed == 2
        assert summary.failed == 0
        assert summary.false_positives == 0
        assert summary.precision == 1.0
        assert summary.recall == 1.0

    def test_one_fail(self):
        results = [
            BenchResult(bench_file="a", cwe="863", expect="found", status="PASS", finding_count=2),
            BenchResult(bench_file="b", cwe="863", expect="found", status="FAIL", finding_count=0),
        ]
        summary = compute_metrics(results, "test-provider")
        assert summary.passed == 1
        assert summary.failed == 1
        assert summary.recall == 0.5

    def test_one_fp(self):
        results = [
            BenchResult(bench_file="a", cwe="863", expect="found", status="PASS", finding_count=2),
            BenchResult(bench_file="b", cwe="863", expect="not_found", status="FP", finding_count=1),
        ]
        summary = compute_metrics(results, "test-provider")
        assert summary.false_positives == 1
        assert summary.precision == 0.5
        assert summary.recall == 1.0

    def test_empty_results(self):
        summary = compute_metrics([], "test-provider")
        assert summary.total == 0
        assert summary.precision == 1.0
        assert summary.recall == 1.0

    def test_all_fail(self):
        results = [
            BenchResult(bench_file="a", cwe="863", expect="found", status="FAIL", finding_count=0),
            BenchResult(bench_file="b", cwe="200", expect="found", status="FAIL", finding_count=0),
        ]
        summary = compute_metrics(results, "test-provider")
        assert summary.recall == 0.0
        assert summary.precision == 1.0  # no FPs, so precision is perfect


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_severity_meets_minimum(self):
        assert _severity_meets_minimum("CRITICAL", "HIGH") is True
        assert _severity_meets_minimum("HIGH", "HIGH") is True
        assert _severity_meets_minimum("MEDIUM", "HIGH") is False
        assert _severity_meets_minimum("LOW", "MEDIUM") is False
        assert _severity_meets_minimum("HIGH", "LOW") is True

    def test_check_evidence_empty_keywords(self):
        assert _check_evidence([], []) is True

    def test_check_evidence_keyword_in_evidence(self):
        f = _mock_finding(evidence="DeleteContact method called here")
        assert _check_evidence([f], ["DeleteContact"]) is True

    def test_check_evidence_keyword_in_description(self):
        f = _mock_finding(description="The DeleteContact endpoint lacks auth")
        assert _check_evidence([f], ["DeleteContact"]) is True

    def test_check_evidence_keyword_in_title(self):
        f = _mock_finding(title="Missing auth on DeleteContact")
        assert _check_evidence([f], ["DeleteContact"]) is True

    def test_check_evidence_case_insensitive(self):
        f = _mock_finding(evidence="deletecontact method")
        assert _check_evidence([f], ["DeleteContact"]) is True

    def test_check_evidence_keyword_not_found(self):
        f = _mock_finding(evidence="something unrelated")
        assert _check_evidence([f], ["DeleteContact"]) is False

    def test_check_evidence_all_keywords_required(self):
        f1 = _mock_finding(evidence="DeleteContact")
        f2 = _mock_finding(evidence="UpdateContact")
        assert _check_evidence([f1, f2], ["DeleteContact", "UpdateContact"]) is True
        assert _check_evidence([f1], ["DeleteContact", "UpdateContact"]) is False
