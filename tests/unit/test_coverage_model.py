"""Tests for the coverage model."""

from security_review.models.coverage import CoverageReport, FileCoverage


class TestFileCoverage:
    def test_strong_coverage(self):
        cov = FileCoverage(file_type="csharp", deterministic_tools=["opengrep"], semantic_passes=["Holistic"])
        assert cov.coverage_level == "strong"
        assert "only" not in cov.summary

    def test_weak_coverage_semantic_only(self):
        cov = FileCoverage(file_type="bicep", semantic_passes=["Config Review"])
        assert cov.coverage_level == "weak"
        assert "only" in cov.summary

    def test_weak_coverage_deterministic_only(self):
        cov = FileCoverage(file_type="python", deterministic_tools=["bandit"])
        assert cov.coverage_level == "weak"
        assert "only" in cov.summary

    def test_no_coverage(self):
        cov = FileCoverage(file_type="unknown")
        assert cov.coverage_level == "none"
        assert cov.summary == "no coverage"

    def test_summary_lists_tools(self):
        cov = FileCoverage(
            file_type="csharp",
            deterministic_tools=["opengrep", "roslyn"],
            semantic_passes=["Holistic"],
        )
        assert "opengrep" in cov.summary
        assert "roslyn" in cov.summary
        assert "LLM Holistic" in cov.summary


class TestCoverageReport:
    def test_weak_types(self):
        report = CoverageReport(by_type={
            "csharp": FileCoverage(file_type="csharp", deterministic_tools=["opengrep"], semantic_passes=["Holistic"]),
            "bicep": FileCoverage(file_type="bicep", semantic_passes=["Config Review"]),
        })
        assert "bicep" in report.weak_types
        assert "csharp" not in report.weak_types

    def test_uncovered_types(self):
        report = CoverageReport(by_type={
            "csharp": FileCoverage(file_type="csharp", deterministic_tools=["opengrep"], semantic_passes=["Holistic"]),
            "other": FileCoverage(file_type="other"),
        })
        assert "other" in report.uncovered_types
        assert "csharp" not in report.uncovered_types

    def test_empty_report(self):
        report = CoverageReport()
        assert report.weak_types == []
        assert report.uncovered_types == []
