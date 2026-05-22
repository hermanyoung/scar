"""Tests for the scoring engine — normalizers, dimensions, composite."""

import math

import pytest

from code_analysis.models import FileMetrics, ProjectMetrics, ReferenceEdge, ReferenceGraph
from code_quality.models import DimensionScore, QualityBand, ToolResult, WEIGHT_PROFILES
from code_quality.scoring import (
    classify_band,
    compute_pqi,
    exp_decay,
    inverse_linear,
    ratio_score,
    score_elegance,
    score_maintainability,
    score_modularity,
    score_reusability,
    score_robustness,
    score_security,
    score_testability,
    sigmoid,
    _floor_penalty,
    _gini_coefficient,
)


# -- Normalizer Tests --------------------------------------------------------


class TestNormalizers:
    def test_sigmoid_at_zero(self):
        # At x=0 with midpoint > 0, should be close to 100
        result = sigmoid(0, midpoint=10, k=0.5)
        assert result > 95.0

    def test_sigmoid_at_midpoint(self):
        result = sigmoid(10, midpoint=10, k=0.5)
        assert abs(result - 50.0) < 1.0

    def test_sigmoid_far_past_midpoint(self):
        result = sigmoid(100, midpoint=10, k=0.5)
        assert result < 5.0

    def test_exp_decay_at_zero(self):
        assert exp_decay(0, rate=0.5) == 100.0

    def test_exp_decay_decreases(self):
        assert exp_decay(1, rate=0.5) < 100.0
        assert exp_decay(5, rate=0.5) < exp_decay(1, rate=0.5)

    def test_exp_decay_never_negative(self):
        assert exp_decay(1000, rate=1.0) >= 0.0

    def test_inverse_linear_at_good(self):
        assert inverse_linear(200, good=200, bad=800) == 100.0

    def test_inverse_linear_at_bad(self):
        assert inverse_linear(800, good=200, bad=800) == 0.0

    def test_inverse_linear_midpoint(self):
        result = inverse_linear(500, good=200, bad=800)
        assert abs(result - 50.0) < 1.0

    def test_inverse_linear_clamped(self):
        assert inverse_linear(0, good=200, bad=800) == 100.0
        assert inverse_linear(1000, good=200, bad=800) == 0.0

    def test_ratio_score_full(self):
        assert ratio_score(10, 10) == 100.0

    def test_ratio_score_half(self):
        assert ratio_score(5, 10) == 50.0

    def test_ratio_score_zero_denom(self):
        assert ratio_score(5, 0) == 100.0


# -- Helpers -----------------------------------------------------------------


def _make_file(
    path: str = "src/main.py",
    language: str = "python",
    lines: int = 100,
    functions: int = 5,
    classes: int = 1,
    documented: int = 3,
    total_callables: int = 6,
    annotated_params: int = 10,
    total_params: int = 10,
    annotated_returns: int = 5,
    total_returns: int = 5,
    max_nesting: int = 2,
    function_lengths: list[int] | None = None,
    naming_violations: int = 0,
    unsafe_calls: list[str] | None = None,
    bare_excepts: int = 0,
    broad_excepts: int = 0,
    exception_handlers: int = 2,
    public_definitions: int = 4,
    private_definitions: int = 2,
) -> FileMetrics:
    return FileMetrics(
        path=path, language=language, lines=lines,
        functions=functions, classes=classes, methods=0,
        documented_callables=documented, total_callables=total_callables,
        annotated_params=annotated_params, total_params=total_params,
        annotated_returns=annotated_returns, total_returns=total_returns,
        max_nesting=max_nesting,
        function_lengths=function_lengths or [20, 25, 30, 15, 10],
        naming_violations=naming_violations,
        unsafe_calls=unsafe_calls or [],
        bare_excepts=bare_excepts, broad_excepts=broad_excepts,
        exception_handlers=exception_handlers,
        public_definitions=public_definitions,
        private_definitions=private_definitions,
    )


def _make_project(
    source_count: int = 5,
    test_count: int = 3,
    **file_kwargs,
) -> ProjectMetrics:
    source_files = [_make_file(path=f"src/mod{i}.py", **file_kwargs) for i in range(source_count)]
    test_files = [_make_file(path=f"tests/test_mod{i}.py", lines=80) for i in range(test_count)]
    return ProjectMetrics(
        files=source_files + test_files,
        source_files=source_count,
        source_lines=sum(f.lines for f in source_files),
        test_files=test_count,
        test_lines=sum(f.lines for f in test_files),
    )


# -- Dimension Scorer Tests --------------------------------------------------


class TestMaintainability:
    def test_well_documented_scores_high(self):
        project = _make_project(documented=6, total_callables=6)
        result = score_maintainability(project)
        assert result.score > 70.0

    def test_undocumented_scores_lower(self):
        project = _make_project(documented=0, total_callables=6)
        result = score_maintainability(project)
        assert result.score < 70.0
        assert any("docstrings" in r.lower() for r in result.recommendations)

    def test_empty_project(self):
        project = ProjectMetrics()
        result = score_maintainability(project)
        assert result.score == 50.0
        assert result.confidence == 0.3


class TestSecurity:
    def test_clean_code_scores_high(self):
        project = _make_project(unsafe_calls=[])
        result = score_security(project)
        assert result.score > 90.0

    def test_unsafe_code_scores_lower(self):
        project = _make_project(unsafe_calls=["line 5: eval() detected"])
        result = score_security(project)
        assert result.score < 90.0

    def test_confidence_without_bandit(self):
        project = _make_project()
        result = score_security(project)
        assert result.confidence == 0.5

    def test_confidence_with_bandit(self):
        project = _make_project()
        tools = {"bandit": ToolResult(
            tool="bandit", available=True,
            metrics={"weighted_per_kloc": 0, "high_severity": 0, "medium_severity": 0},
        )}
        result = score_security(project, tools)
        assert result.confidence == 0.9


class TestModularity:
    def test_no_graph_low_confidence(self):
        project = ProjectMetrics(files=[_make_file()], source_files=1, source_lines=100)
        result = score_modularity(project)
        assert result.confidence == 0.3
        assert result.score == 50.0

    def test_with_graph(self):
        graph = ReferenceGraph(
            nodes=["A", "B", "C"],
            edges=[ReferenceEdge("A", "B"), ReferenceEdge("B", "C")],
        )
        project = ProjectMetrics(
            files=[_make_file(path=f"src/{n}.py") for n in ["a", "b", "c"]],
            graph=graph, source_files=3, source_lines=300,
        )
        result = score_modularity(project)
        assert result.confidence == 1.0
        assert 0 < result.score <= 100


class TestRobustness:
    def test_fully_typed_scores_high(self):
        project = _make_project(annotated_params=10, total_params=10,
                                annotated_returns=5, total_returns=5)
        result = score_robustness(project)
        assert result.score > 80.0

    def test_untyped_scores_lower(self):
        project = _make_project(annotated_params=0, total_params=10,
                                annotated_returns=0, total_returns=5)
        result = score_robustness(project)
        assert result.score < 50.0

    def test_bare_excepts_reduce_score(self):
        good = _make_project(bare_excepts=0, exception_handlers=5)
        bad = _make_project(bare_excepts=5, exception_handlers=5)
        assert score_robustness(good).score > score_robustness(bad).score


class TestElegance:
    def test_shallow_nesting_scores_high(self):
        project = _make_project(max_nesting=2, function_lengths=[15, 20, 10])
        result = score_elegance(project)
        assert result.score > 70.0

    def test_deep_nesting_scores_lower(self):
        project = _make_project(max_nesting=7, function_lengths=[80, 90, 100])
        result = score_elegance(project)
        assert result.score < 50.0


class TestTestability:
    def test_good_test_ratio(self):
        project = ProjectMetrics(
            files=[_make_file()], source_files=5, source_lines=500,
            test_files=5, test_lines=500,
        )
        result = score_testability(project)
        assert result.score > 50.0

    def test_no_tests(self):
        project = ProjectMetrics(
            files=[_make_file()], source_files=5, source_lines=500,
            test_files=0, test_lines=0,
        )
        result = score_testability(project)
        assert any("no test" in r.lower() for r in result.recommendations)


# -- Composite Tests ---------------------------------------------------------


class TestComposite:
    def test_geometric_mean(self):
        dims = {name: DimensionScore(name=name, score=80.0) for name in WEIGHT_PROFILES["production"]}
        result = compute_pqi(dims, profile="production")
        # All 80 → geometric mean should be 80
        assert abs(result.composite - 80.0) < 1.0

    def test_band_classification(self):
        assert classify_band(85) == QualityBand.EXCELLENT
        assert classify_band(70) == QualityBand.GOOD
        assert classify_band(60) == QualityBand.ADEQUATE
        assert classify_band(40) == QualityBand.ACCEPTABLE
        assert classify_band(20) == QualityBand.POOR

    def test_floor_penalty_applied(self):
        dims = {name: DimensionScore(name=name, score=80.0) for name in WEIGHT_PROFILES["production"]}
        dims["security"] = DimensionScore(name="Security", score=10.0)  # below floor
        result = compute_pqi(dims, profile="production")
        assert result.floor_penalty < 1.0
        assert result.composite < 80.0

    def test_floor_penalty_not_applied_above_threshold(self):
        dims = {name: DimensionScore(name=name, score=50.0) for name in WEIGHT_PROFILES["production"]}
        result = compute_pqi(dims, profile="production")
        assert result.floor_penalty == 1.0

    def test_weight_profiles_sum_to_one(self):
        for name, weights in WEIGHT_PROFILES.items():
            total = sum(weights.values())
            assert abs(total - 1.0) < 0.001, f"Profile {name} sums to {total}"

    def test_deterministic(self):
        dims = {name: DimensionScore(name=name, score=65.0) for name in WEIGHT_PROFILES["production"]}
        r1 = compute_pqi(dims, "production")
        r2 = compute_pqi(dims, "production")
        assert r1.composite == r2.composite


class TestGini:
    def test_equal_values(self):
        assert _gini_coefficient([100, 100, 100, 100]) == 0.0

    def test_unequal_values(self):
        gini = _gini_coefficient([1, 1, 1, 1000])
        assert gini > 0.5

    def test_empty(self):
        assert _gini_coefficient([]) == 0.0

    def test_single_value(self):
        assert _gini_coefficient([42]) == 0.0
