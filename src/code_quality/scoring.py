"""Pure scoring engine — normalizers, dimension scorers, and composite.

All functions in this module are pure (no I/O, no side effects).
They take ProjectMetrics + optional ToolResults and produce scores.
"""

from __future__ import annotations

import math
import statistics

from code_analysis.models import FileMetrics, ProjectMetrics
from code_quality.models import (
    DimensionScore,
    PQIResult,
    QualityBand,
    ToolResult,
    WEIGHT_PROFILES,
)


# -- Normalizers -------------------------------------------------------------


def sigmoid(x: float, midpoint: float, k: float = 0.5) -> float:
    """Sigmoid decay: 100 at x=0, drops around midpoint."""
    return 100.0 / (1.0 + math.exp(k * (x - midpoint)))


def exp_decay(count: float, rate: float = 0.5) -> float:
    """Exponential decay: 100 at count=0, decays at rate."""
    return 100.0 * math.exp(-rate * count)


def inverse_linear(value: float, good: float, bad: float) -> float:
    """Linear score: 100 at 'good', 0 at 'bad'."""
    if bad == good:
        return 100.0 if value <= good else 0.0
    score = 100.0 * (bad - value) / (bad - good)
    return max(0.0, min(100.0, score))


def ratio_score(numerator: float, denominator: float) -> float:
    """Ratio as percentage, clamped to 0-100."""
    if denominator <= 0:
        return 100.0
    return max(0.0, min(100.0, (numerator / denominator) * 100.0))


# -- Helpers -----------------------------------------------------------------


def _source_files(metrics: ProjectMetrics) -> list[FileMetrics]:
    """Filter to non-test source files."""
    return [
        f for f in metrics.files
        if "/tests/" not in f.path
        and not f.path.startswith("tests/")
        and "/test_" not in f.path
        and not f.path.startswith("test_")
    ]


def _primary_language(files: list[FileMetrics]) -> str:
    """Determine the dominant language in a file list."""
    counts: dict[str, int] = {}
    for f in files:
        counts[f.language] = counts.get(f.language, 0) + 1
    if not counts:
        return "python"
    return max(counts, key=counts.get)  # type: ignore[arg-type]


# -- Dimension Scorers -------------------------------------------------------


def score_maintainability(
    metrics: ProjectMetrics, tools: dict[str, ToolResult] | None = None,
) -> DimensionScore:
    tools = tools or {}
    source = _source_files(metrics)
    if not source:
        return DimensionScore(name="Maintainability", score=50.0, confidence=0.3)

    total_callables = sum(f.total_callables for f in source)
    documented = sum(f.documented_callables for f in source)
    doc_coverage = ratio_score(documented, total_callables)

    sizes = sorted(f.lines for f in source)
    p90_size = sizes[min(int(len(sizes) * 0.9), len(sizes) - 1)]
    file_size_score = inverse_linear(p90_size, good=200, bad=800)

    all_lengths: list[int] = []
    for f in source:
        all_lengths.extend(f.function_lengths)
    if all_lengths:
        p90_length = sorted(all_lengths)[min(int(len(all_lengths) * 0.9), len(all_lengths) - 1)]
        func_length_score = inverse_linear(p90_length, good=30, bad=100)
    else:
        p90_length = 0
        func_length_score = 100.0

    sub_scores = {
        "doc_coverage": doc_coverage,
        "file_size_p90": file_size_score,
        "function_length_p90": func_length_score,
    }
    recommendations: list[str] = []

    radon = tools.get("radon")
    if radon and radon.success:
        avg_mi = radon.metrics.get("avg_mi", 50.0)
        mi_score = min(100.0, max(0.0, avg_mi))
        sub_scores["radon_mi"] = mi_score
        score = doc_coverage * 0.25 + file_size_score * 0.20 + func_length_score * 0.25 + mi_score * 0.30
        if avg_mi < 40:
            recommendations.append(f"Average maintainability index is {avg_mi:.0f} -- refactor complex modules")
    else:
        avg_funcs = statistics.mean(f.functions for f in source) if source else 0
        cohesion_score = sigmoid(avg_funcs, midpoint=15, k=0.2)
        sub_scores["cohesion"] = cohesion_score
        score = doc_coverage * 0.30 + file_size_score * 0.25 + func_length_score * 0.25 + cohesion_score * 0.20

    if doc_coverage < 50:
        recommendations.append(f"Documentation coverage is {doc_coverage:.0f}% -- add docstrings")
    if p90_size > 500:
        recommendations.append(f"P90 file size is {p90_size} lines -- split large files")
    if p90_length > 50:
        recommendations.append(f"P90 function length is {p90_length} lines -- extract helpers")

    return DimensionScore(
        name="Maintainability", score=score, sub_scores=sub_scores,
        recommendations=recommendations,
    )


def score_security(
    metrics: ProjectMetrics, tools: dict[str, ToolResult] | None = None,
) -> DimensionScore:
    tools = tools or {}
    source = _source_files(metrics)
    if not source:
        return DimensionScore(name="Security", score=50.0, confidence=0.3)

    kloc = max(metrics.source_lines / 1000, 0.1)
    total_unsafe = sum(len(f.unsafe_calls) for f in source)
    unsafe_per_kloc = total_unsafe / kloc
    ast_unsafe_score = exp_decay(unsafe_per_kloc, rate=1.0)

    files_with_unsafe = sum(1 for f in source if f.unsafe_calls)
    ast_clean_ratio = ratio_score(len(source) - files_with_unsafe, len(source))

    sub_scores = {
        "ast_unsafe_patterns": ast_unsafe_score,
        "ast_clean_file_ratio": ast_clean_ratio,
    }
    recommendations: list[str] = []
    confidence = 0.5

    bandit = tools.get("bandit")
    if bandit and bandit.success:
        confidence = 0.9
        m = bandit.metrics
        bandit_density = exp_decay(m.get("weighted_per_kloc", 0), rate=0.3)
        bandit_high = exp_decay(int(m.get("high_severity", 0)), rate=1.5)
        bandit_med = exp_decay(int(m.get("medium_severity", 0)), rate=0.5)
        sub_scores.update({
            "bandit_severity_density": bandit_density,
            "bandit_high_severity": bandit_high,
            "bandit_medium_severity": bandit_med,
        })
        score = (bandit_density * 0.30 + bandit_high * 0.25 + bandit_med * 0.15
                 + ast_unsafe_score * 0.15 + ast_clean_ratio * 0.15)
        if int(m.get("high_severity", 0)) > 0:
            recommendations.append(f"{int(m['high_severity'])} HIGH severity finding(s) -- fix immediately")
        if int(m.get("medium_severity", 0)) > 0:
            recommendations.append(f"{int(m['medium_severity'])} MEDIUM severity finding(s)")
    else:
        score = ast_unsafe_score * 0.60 + ast_clean_ratio * 0.40
        if not bandit:
            recommendations.append("Install bandit for deeper security analysis: pip install bandit")

    return DimensionScore(
        name="Security", score=score, sub_scores=sub_scores,
        confidence=confidence, recommendations=recommendations,
    )


def score_modularity(metrics: ProjectMetrics) -> DimensionScore:
    if metrics.graph is None or not metrics.graph.nodes:
        return DimensionScore(
            name="Modularity", score=50.0, confidence=0.3,
            recommendations=["Run with include_graph=True for accurate modularity scoring"],
        )

    graph = metrics.graph
    # Compute efferent coupling (Ce) per module
    ce: dict[str, int] = {}
    ca: dict[str, int] = {}
    for edge in graph.edges:
        ce[edge.source] = ce.get(edge.source, 0) + 1
        ca[edge.target] = ca.get(edge.target, 0) + 1

    all_modules = set(ce.keys()) | set(ca.keys())
    instabilities = []
    for m in all_modules:
        c_e = ce.get(m, 0)
        c_a = ca.get(m, 0)
        if c_e + c_a > 0:
            instabilities.append(c_e / (c_e + c_a))

    instability_score = (
        100.0 * (1.0 - abs(statistics.mean(instabilities) - 0.5) * 2)
        if instabilities else 50.0
    )

    max_ce = max(ce.values()) if ce else 0
    coupling_score = sigmoid(max_ce, midpoint=15, k=0.3)

    cycle_count = _count_cycles(ce, graph)
    cycle_score = exp_decay(cycle_count, rate=1.0)

    # Size distribution (Gini coefficient)
    source = _source_files(metrics)
    sizes = [f.lines for f in source]
    gini = _gini_coefficient(sizes) if len(sizes) > 1 else 0.0
    gini_score = (1.0 - gini) * 100.0

    score = (instability_score * 0.25 + coupling_score * 0.30
             + cycle_score * 0.25 + gini_score * 0.20)

    recommendations = []
    if max_ce > 15:
        recommendations.append(f"Max efferent coupling is {max_ce} -- too many dependencies")
    if cycle_count > 0:
        recommendations.append(f"{cycle_count} circular dependency(ies) -- break with protocols")

    return DimensionScore(
        name="Modularity", score=score,
        sub_scores={
            "instability_balance": instability_score,
            "coupling_max_ce": coupling_score,
            "circular_deps": cycle_score,
            "size_gini": gini_score,
        },
        recommendations=recommendations,
    )


def score_testability(
    metrics: ProjectMetrics, tools: dict[str, ToolResult] | None = None,
) -> DimensionScore:
    tools = tools or {}
    source = _source_files(metrics)
    if not source:
        return DimensionScore(name="Testability", score=50.0, confidence=0.3)

    test_ratio = metrics.test_lines / metrics.source_lines if metrics.source_lines > 0 else 0.0
    ratio_score_val = sigmoid(abs(test_ratio - 1.0), midpoint=0.8, k=3.0) if metrics.source_lines > 0 else 0.0

    file_ratio = metrics.test_files / metrics.source_files if metrics.source_files > 0 else 0.0
    file_ratio_score = min(100.0, file_ratio * 100.0)

    max_nestings = [f.max_nesting for f in source if f.max_nesting > 0]
    nesting_score = sigmoid(statistics.mean(max_nestings), midpoint=4, k=1.0) if max_nestings else 100.0

    sub_scores = {
        "test_code_ratio": ratio_score_val,
        "test_file_ratio": file_ratio_score,
        "avg_nesting_depth": nesting_score,
    }
    recommendations: list[str] = []

    radon = tools.get("radon")
    if radon and radon.success:
        avg_cc = radon.metrics.get("avg_complexity", 5.0)
        complexity_score = sigmoid(avg_cc, midpoint=10, k=0.3)
        simple_score = radon.metrics.get("simple_ratio", 1.0) * 100.0
        sub_scores.update({
            "radon_avg_complexity": complexity_score,
            "simple_function_ratio": simple_score,
        })
        score = (ratio_score_val * 0.30 + file_ratio_score * 0.15
                 + complexity_score * 0.25 + simple_score * 0.15 + nesting_score * 0.15)
    else:
        all_lengths = [length for f in source for length in f.function_lengths]
        length_score = sigmoid(statistics.mean(all_lengths), midpoint=25, k=0.15) if all_lengths else 100.0
        sub_scores["avg_function_length"] = length_score
        score = ratio_score_val * 0.35 + file_ratio_score * 0.20 + length_score * 0.25 + nesting_score * 0.20

    if test_ratio < 0.5:
        recommendations.append(f"Test-to-code ratio is {test_ratio:.2f} -- aim for 0.8-1.2")
    if metrics.test_files == 0:
        recommendations.append("No test files found")

    return DimensionScore(
        name="Testability", score=score, sub_scores=sub_scores,
        recommendations=recommendations,
    )


def score_robustness(metrics: ProjectMetrics) -> DimensionScore:
    source = _source_files(metrics)
    if not source:
        return DimensionScore(name="Robustness", score=50.0, confidence=0.3)

    # Language-agnostic: exception handling quality
    total_handlers = sum(f.exception_handlers for f in source)
    bad_handlers = sum(f.bare_excepts for f in source) + sum(f.broad_excepts for f in source)
    handler_quality = (1.0 - bad_handlers / total_handlers) * 100.0 if total_handlers > 0 else 100.0

    # Language-specific: type safety signals
    lang = _primary_language(source)
    if lang == "csharp":
        type_safety = _score_csharp_type_safety(source)
    else:
        type_safety = _score_python_type_coverage(source)

    score = type_safety * 0.65 + handler_quality * 0.35

    sub_scores = {"type_safety": type_safety, "exception_handling_quality": handler_quality}
    recommendations = []

    if type_safety < 70:
        if lang == "csharp":
            recommendations.append("Enable #nullable across all files")
        else:
            recommendations.append(f"Type coverage is {type_safety:.0f}% -- add annotations")
    if sum(f.bare_excepts for f in source) > 0:
        recommendations.append(f"{sum(f.bare_excepts for f in source)} bare/swallowed except(s)")

    return DimensionScore(
        name="Robustness", score=score, sub_scores=sub_scores,
        recommendations=recommendations,
    )


def score_elegance(
    metrics: ProjectMetrics, tools: dict[str, ToolResult] | None = None,
) -> DimensionScore:
    tools = tools or {}
    source = _source_files(metrics)
    if not source:
        return DimensionScore(name="Elegance", score=50.0, confidence=0.3)

    nestings = [f.max_nesting for f in source]
    p90_nesting = sorted(nestings)[min(int(len(nestings) * 0.9), len(nestings) - 1)] if nestings else 0
    nesting_score = sigmoid(p90_nesting, midpoint=4, k=1.5)

    all_lengths = [length for f in source for length in f.function_lengths]
    if all_lengths:
        p90_length = sorted(all_lengths)[min(int(len(all_lengths) * 0.9), len(all_lengths) - 1)]
        length_score = inverse_linear(p90_length, good=30, bad=100)
    else:
        p90_length = 0
        length_score = 100.0

    total_defs = sum(f.functions + f.classes for f in source)
    total_violations = sum(f.naming_violations for f in source)
    naming_score = (1.0 - total_violations / total_defs) * 100.0 if total_defs > 0 else 100.0

    sub_scores = {
        "nesting_depth_p90": nesting_score,
        "function_length_p90": length_score,
        "naming_conventions": naming_score,
    }
    recommendations: list[str] = []

    radon = tools.get("radon")
    if radon and radon.success:
        p90_cc = radon.metrics.get("p90_complexity", 5)
        cc_score = sigmoid(p90_cc, midpoint=10, k=0.4)
        sub_scores["radon_complexity_p90"] = cc_score
        score = nesting_score * 0.25 + length_score * 0.25 + naming_score * 0.25 + cc_score * 0.25
    else:
        score = nesting_score * 0.35 + length_score * 0.35 + naming_score * 0.30

    if p90_nesting > 4:
        recommendations.append(f"P90 nesting depth is {p90_nesting} -- extract nested logic")
    if p90_length > 50:
        recommendations.append(f"P90 function length is {p90_length} lines -- break into smaller functions")

    return DimensionScore(
        name="Elegance", score=score, sub_scores=sub_scores,
        recommendations=recommendations,
    )


def score_reusability(metrics: ProjectMetrics) -> DimensionScore:
    source = _source_files(metrics)
    if not source:
        return DimensionScore(name="Reusability", score=50.0, confidence=0.3)

    total_public = sum(f.public_definitions for f in source)
    total_private = sum(f.private_definitions for f in source)
    total_defs = total_public + total_private

    if total_defs > 0:
        api_ratio = total_public / total_defs
        if 0.3 <= api_ratio <= 0.6:
            api_score = 100.0
        elif api_ratio < 0.3:
            api_score = api_ratio / 0.3 * 100.0
        else:
            api_score = max(0.0, 100.0 - (api_ratio - 0.6) / 0.4 * 100.0)
    else:
        api_ratio = 0.0
        api_score = 50.0

    # Coupling from graph
    if metrics.graph and metrics.graph.edges:
        ce_values: list[int] = []
        for edge in metrics.graph.edges:
            ce_values.append(1)  # count edges per source
        ce_per_module: dict[str, int] = {}
        for edge in metrics.graph.edges:
            ce_per_module[edge.source] = ce_per_module.get(edge.source, 0) + 1
        avg_ce = statistics.mean(ce_per_module.values()) if ce_per_module else 0
        coupling_score = sigmoid(avg_ce, midpoint=8, k=0.4)
    else:
        coupling_score = 50.0

    size_score = sigmoid(
        statistics.mean(f.lines for f in source), midpoint=200, k=0.02
    )

    score = api_score * 0.35 + coupling_score * 0.35 + size_score * 0.30

    recommendations = []
    if total_defs > 0 and api_ratio > 0.7:
        recommendations.append(
            f"API surface is {api_ratio:.0%} public -- consider making more internals private"
        )

    return DimensionScore(
        name="Reusability", score=score,
        sub_scores={"api_surface_ratio": api_score, "coupling": coupling_score, "module_size": size_score},
        recommendations=recommendations,
    )


# -- Composite PQI -----------------------------------------------------------


CRITICAL_FLOOR = 20


def classify_band(score: float) -> QualityBand:
    if score >= 80:
        return QualityBand.EXCELLENT
    if score >= 65:
        return QualityBand.GOOD
    if score >= 55:
        return QualityBand.ADEQUATE
    if score >= 31:
        return QualityBand.ACCEPTABLE
    return QualityBand.POOR


def compute_pqi(
    dimensions: dict[str, DimensionScore],
    profile: str = "production",
    file_count: int = 0,
    line_count: int = 0,
) -> PQIResult:
    """Compute the composite PQI score using weighted geometric mean."""
    weights = WEIGHT_PROFILES.get(profile, WEIGHT_PROFILES["production"])
    scores = {k: max(1.0, v.score) for k, v in dimensions.items()}

    log_sum = sum(
        w * math.log(scores.get(d, 50.0)) for d, w in weights.items()
    )
    geometric_mean = math.exp(log_sum)

    penalty = _floor_penalty(scores)
    composite = min(100.0, geometric_mean * penalty)

    return PQIResult(
        composite=round(composite, 1),
        dimensions=dimensions,
        quality_band=classify_band(composite),
        floor_penalty=round(penalty, 3),
        file_count=file_count,
        line_count=line_count,
    )


def _floor_penalty(dimension_scores: dict[str, float]) -> float:
    """Penalize if any dimension falls below CRITICAL_FLOOR."""
    violations = [s for s in dimension_scores.values() if s < CRITICAL_FLOOR]
    if not violations:
        return 1.0
    penalty = 1.0
    for s in violations:
        deficit = (CRITICAL_FLOOR - s) / CRITICAL_FLOOR
        penalty *= (1.0 - 0.3 * deficit)
    return max(0.3, penalty)


# -- Internal helpers --------------------------------------------------------


def _score_python_type_coverage(source: list[FileMetrics]) -> float:
    """Score Python type annotation coverage."""
    param_coverage = ratio_score(
        sum(f.annotated_params for f in source),
        sum(f.total_params for f in source),
    )
    return_coverage = ratio_score(
        sum(f.annotated_returns for f in source),
        sum(f.total_returns for f in source),
    )
    return param_coverage * 0.55 + return_coverage * 0.45


def _score_csharp_type_safety(source: list[FileMetrics]) -> float:
    """Score C# nullable safety signals."""
    total_files = len(source)
    if total_files == 0:
        return 100.0

    # Nullable enabled ratio
    nullable_files = sum(1 for f in source if f.nullable_enabled)
    nullable_score = ratio_score(nullable_files, total_files)

    # Null-forgiving operator abuse (fewer is better)
    total_forgiving = sum(f.null_forgiving_count for f in source)
    kloc = max(sum(f.lines for f in source) / 1000, 0.1)
    forgiving_per_kloc = total_forgiving / kloc
    forgiving_score = exp_decay(forgiving_per_kloc, rate=0.5)

    return nullable_score * 0.60 + forgiving_score * 0.40


def _count_cycles(ce: dict[str, int], graph) -> int:
    """Count circular dependencies using iterative DFS.

    Iterative to avoid Python's recursion limit on large module graphs.
    Each stack frame carries (node, iterator-over-neighbors, entered-rec_stack).
    """
    adj: dict[str, list[str]] = {}
    for edge in graph.edges:
        adj.setdefault(edge.source, []).append(edge.target)

    visited: set[str] = set()
    rec_stack: set[str] = set()
    cycles = 0

    for start in adj:
        if start in visited:
            continue
        # Stack entries: (node, neighbor_iterator, added_to_rec_stack)
        stack: list[tuple[str, object, bool]] = [(start, iter(adj.get(start, [])), True)]
        visited.add(start)
        rec_stack.add(start)

        while stack:
            node, neighbors, in_rec = stack[-1]
            neighbor = next(neighbors, None)  # type: ignore[call-overload]
            if neighbor is None:
                # Done with this node — pop and remove from recursion stack
                stack.pop()
                if in_rec:
                    rec_stack.discard(node)
            elif neighbor not in visited:
                visited.add(neighbor)
                rec_stack.add(neighbor)
                stack.append((neighbor, iter(adj.get(neighbor, [])), True))
            elif neighbor in rec_stack:
                cycles += 1

    return cycles


def _gini_coefficient(values: list[int | float]) -> float:
    """Compute Gini coefficient for size distribution."""
    if not values or len(values) < 2:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    total = sum(sorted_vals)
    if total == 0:
        return 0.0
    cumulative = sum((2 * (i + 1) - n - 1) * v for i, v in enumerate(sorted_vals))
    return cumulative / (n * total)


# -- Security review integration ----------------------------------------------


def override_security_from_review(
    quality_result: PQIResult,
    urgent: int,
    elevated: int,
    total: int,
) -> None:
    """Replace AST-only Security score with actual review findings.

    The quality Security dimension only detects AST patterns (eval, pickle).
    After a full review, we have real findings (IDOR, authZ, injection, etc.)
    that should drive the score instead.

    Mutates quality_result in place.
    """
    critical_score = exp_decay(urgent, rate=1.5)
    elevated_score = exp_decay(elevated, rate=0.5)
    volume_score = exp_decay(total, rate=0.15)

    score = critical_score * 0.50 + elevated_score * 0.25 + volume_score * 0.25

    recommendations: list[str] = []
    if urgent > 0:
        recommendations.append(f"{urgent} URGENT finding(s) — fix immediately")
    if elevated > 0:
        recommendations.append(f"{elevated} ELEVATED finding(s)")

    quality_result.dimensions["security"] = DimensionScore(
        name="Security", score=score, confidence=1.0,
        sub_scores={
            "urgent_findings": critical_score,
            "elevated_findings": elevated_score,
            "total_findings_volume": volume_score,
        },
        recommendations=recommendations,
    )

    # Recompute composite via compute_pqi (single source of truth for scoring)
    recomputed = compute_pqi(
        quality_result.dimensions,
        profile="production",
        file_count=quality_result.file_count,
        line_count=quality_result.line_count,
    )
    quality_result.composite = recomputed.composite
    quality_result.quality_band = recomputed.quality_band
    quality_result.floor_penalty = recomputed.floor_penalty
