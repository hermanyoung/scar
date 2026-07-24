#!/usr/bin/env python3
"""Score codebase quality using the PyQuality Index (PQI).

Produces a composite 0-100 score across 7 dimensions:
Maintainability, Security, Modularity, Testability, Robustness,
Elegance, and Reusability.

Usage:
    python scripts/code_quality.py                           # Score src/
    python scripts/code_quality.py --scope src/              # Specific directory
    python scripts/code_quality.py --profile safety_critical # Security-tool weights
    python scripts/code_quality.py --json                    # JSON output
    python scripts/code_quality.py --recommendations         # Show improvement tips
    python scripts/code_quality.py --no-bandit --no-radon    # AST-only (no external tools)
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import re
import shutil
import statistics
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# -- Types -------------------------------------------------------------------


class QualityBand(str, Enum):
    POOR = "Poor"              # 0-30
    ACCEPTABLE = "Acceptable"  # 31-54
    ADEQUATE = "Adequate"      # 55-64
    GOOD = "Good"              # 65-79
    EXCELLENT = "Excellent"    # 80-100


@dataclass
class DimensionScore:
    name: str
    score: float
    sub_scores: dict[str, float] = field(default_factory=dict)
    confidence: float = 1.0
    recommendations: list[str] = field(default_factory=list)


@dataclass
class QualityIssue:
    file: str
    line: int
    dimension: str
    severity: str  # HIGH, MEDIUM, LOW
    category: str
    message: str
    tool: str = "ast"
    entity: str = ""
    value: float = 0
    threshold: float = 0

    @property
    def priority(self) -> int:
        return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(self.severity, 3)


@dataclass
class PQIResult:
    composite: float
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    quality_band: QualityBand = QualityBand.POOR
    floor_penalty: float = 1.0
    file_count: int = 0
    line_count: int = 0
    issues: list[QualityIssue] = field(default_factory=list)


WEIGHT_PROFILES: dict[str, dict[str, float]] = {
    "production": {
        "maintainability": 0.20,
        "security": 0.15,
        "modularity": 0.15,
        "testability": 0.15,
        "robustness": 0.13,
        "elegance": 0.12,
        "reusability": 0.10,
    },
    "library": {
        "maintainability": 0.15,
        "security": 0.10,
        "modularity": 0.20,
        "testability": 0.15,
        "robustness": 0.10,
        "elegance": 0.15,
        "reusability": 0.15,
    },
    "safety_critical": {
        "maintainability": 0.15,
        "security": 0.25,
        "modularity": 0.10,
        "testability": 0.20,
        "robustness": 0.15,
        "elegance": 0.05,
        "reusability": 0.10,
    },
}


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


# -- Tool Types --------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    severity: str
    confidence: str
    message: str
    file: str
    line: int
    tool: str


@dataclass
class ToolResult:
    tool: str
    available: bool
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    raw_output: str = ""
    error: str = ""

    @property
    def success(self) -> bool:
        return self.available and not self.error


# -- Normalizers -------------------------------------------------------------


def sigmoid(x: float, midpoint: float, k: float = 0.5) -> float:
    return 100.0 / (1.0 + math.exp(k * (x - midpoint)))


def exp_decay(count: float, rate: float = 0.5) -> float:
    return 100.0 * math.exp(-rate * count)


def linear(value: float, max_value: float = 100.0) -> float:
    return max(0.0, min(100.0, (value / max_value) * 100.0)) if max_value > 0 else 0.0


def inverse_linear(value: float, good: float, bad: float) -> float:
    if bad == good:
        return 100.0 if value <= good else 0.0
    score = 100.0 * (bad - value) / (bad - good)
    return max(0.0, min(100.0, score))


def ratio_score(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 100.0
    return max(0.0, min(100.0, (numerator / denominator) * 100.0))


# -- AST Analysis ------------------------------------------------------------


@dataclass
class FileAnalysis:
    path: str
    lines: int = 0
    functions: int = 0
    classes: int = 0
    methods: int = 0
    documented_callables: int = 0
    total_callables: int = 0
    annotated_params: int = 0
    total_params: int = 0
    annotated_returns: int = 0
    total_returns: int = 0
    exception_handlers: int = 0
    bare_excepts: int = 0
    broad_excepts: int = 0
    max_nesting: int = 0
    function_lengths: list[int] = field(default_factory=list)
    naming_violations: int = 0
    unsafe_calls: list[str] = field(default_factory=list)
    public_definitions: int = 0
    private_definitions: int = 0


@dataclass
class ProjectAnalysis:
    files: list[FileAnalysis] = field(default_factory=list)
    test_files: int = 0
    test_lines: int = 0
    source_files: int = 0
    source_lines: int = 0


UNSAFE_PATTERNS = {
    "eval": "eval() can execute arbitrary code",
    "exec": "exec() can execute arbitrary code",
    "compile": "compile() with exec mode is dangerous",
    "__import__": "dynamic import can be exploited",
}

UNSAFE_ATTR_PATTERNS = {
    ("os", "system"): "os.system() is vulnerable to shell injection",
    ("os", "popen"): "os.popen() is vulnerable to shell injection",
    ("subprocess", "call"): "subprocess.call(shell=True) is dangerous",
    ("pickle", "loads"): "pickle.loads() can execute arbitrary code",
    ("pickle", "load"): "pickle.load() can execute arbitrary code",
    ("yaml", "load"): "yaml.load() without SafeLoader is dangerous",
}


def _collect_files(
    repo_root: Path,
    scope: list[str] | None,
    exclude: list[str] | None,
) -> list[Path]:
    exclude = exclude or []
    exclude_set = set(exclude)

    if scope:
        files: list[Path] = []
        for pattern in scope:
            if pattern.endswith("/"):
                files.extend(repo_root.glob(f"{pattern}**/*.py"))
            elif "*" in pattern:
                files.extend(repo_root.glob(pattern))
            else:
                candidate = repo_root / pattern
                if candidate.is_file() and candidate.suffix == ".py":
                    files.append(candidate)
                elif candidate.is_dir():
                    files.extend(candidate.rglob("*.py"))
        files = list(set(files))
    else:
        files = list(repo_root.rglob("*.py"))

    result = []
    for f in files:
        rel = str(f.relative_to(repo_root))
        if any(_matches_exclude(rel, exc) for exc in exclude_set):
            continue
        result.append(f)
    return result


def _matches_exclude(rel_path: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        return rel_path.startswith(pattern) or rel_path.startswith(pattern.rstrip("/"))
    if "*" in pattern or "?" in pattern or "[" in pattern:
        from fnmatch import fnmatch
        return fnmatch(rel_path, pattern)
    return rel_path.startswith(pattern)


def analyze_file(file_path: Path, rel_path: str) -> FileAnalysis | None:
    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return None

    line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)
    analysis = FileAnalysis(path=rel_path, lines=line_count)

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            analysis.classes += 1
            _analyze_callable(node, analysis, is_class=True)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            analysis.functions += 1
            _analyze_callable(node, analysis, is_class=False)
        elif isinstance(node, ast.ExceptHandler):
            _analyze_except_handler(node, analysis)

    analysis.max_nesting = _compute_max_nesting(tree)
    analysis.unsafe_calls = _detect_unsafe_patterns(tree)
    analysis.naming_violations = _count_naming_violations(tree)
    return analysis


def analyze_project(
    repo_root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
) -> ProjectAnalysis:
    files = _collect_files(repo_root, scope, exclude)
    result = ProjectAnalysis()

    for file_path in sorted(files):
        rel_path = str(file_path.relative_to(repo_root))
        analysis = analyze_file(file_path, rel_path)
        if analysis is None:
            continue

        result.files.append(analysis)

        is_test = (
            "/tests/" in rel_path
            or rel_path.startswith("tests/")
            or rel_path.startswith("test_")
            or "/test_" in rel_path
        )
        if is_test:
            result.test_files += 1
            result.test_lines += analysis.lines
        else:
            result.source_files += 1
            result.source_lines += analysis.lines

    return result


def _analyze_callable(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    analysis: FileAnalysis,
    is_class: bool,
) -> None:
    if isinstance(node, ast.ClassDef):
        analysis.total_callables += 1
        if ast.get_docstring(node):
            analysis.documented_callables += 1
        if node.name.startswith("_"):
            analysis.private_definitions += 1
        else:
            analysis.public_definitions += 1
        return

    analysis.total_callables += 1
    if ast.get_docstring(node):
        analysis.documented_callables += 1

    if node.end_lineno and node.lineno:
        length = node.end_lineno - node.lineno + 1
        analysis.function_lengths.append(length)

    for arg in node.args.args:
        if is_class and arg.arg in ("self", "cls"):
            continue
        analysis.total_params += 1
        if arg.annotation is not None:
            analysis.annotated_params += 1

    analysis.total_returns += 1
    if node.returns is not None:
        analysis.annotated_returns += 1

    if node.name.startswith("_") and not node.name.startswith("__"):
        analysis.private_definitions += 1
    else:
        analysis.public_definitions += 1


def _analyze_except_handler(node: ast.ExceptHandler, analysis: FileAnalysis) -> None:
    analysis.exception_handlers += 1
    if node.type is None:
        analysis.bare_excepts += 1
    elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
        analysis.broad_excepts += 1
    if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
        analysis.bare_excepts += 1


def _compute_max_nesting(tree: ast.Module) -> int:
    max_depth = 0

    def walk(node: ast.AST, depth: int) -> None:
        nonlocal max_depth
        nesting_types = (
            ast.If, ast.For, ast.While, ast.With,
            ast.Try, ast.AsyncFor, ast.AsyncWith,
        )
        if isinstance(node, nesting_types):
            depth += 1
            max_depth = max(max_depth, depth)
        for child in ast.iter_child_nodes(node):
            walk(child, depth)

    walk(tree, 0)
    return max_depth


def _detect_unsafe_patterns(tree: ast.Module) -> list[str]:
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in UNSAFE_PATTERNS:
                findings.append(f"line {node.lineno}: {UNSAFE_PATTERNS[node.func.id]}")
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    key = (node.func.value.id, node.func.attr)
                    if key in UNSAFE_ATTR_PATTERNS:
                        findings.append(f"line {node.lineno}: {UNSAFE_ATTR_PATTERNS[key]}")
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(f"line {node.lineno}: subprocess with shell=True")
    return findings


def _count_naming_violations(tree: ast.Module) -> int:
    violations = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if node.name[0].islower() and not node.name.startswith("_"):
                violations += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
            if not name.startswith("__") and not name.islower() and name != name.lower():
                if any(c.isupper() for c in name[1:]) and "_" not in name:
                    violations += 1
    return violations


# -- External Tools ----------------------------------------------------------


def _check_installed(command: str) -> bool:
    return shutil.which(command) is not None


def _run_command(
    args: list[str], cwd: Path, timeout: int = 120,
) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except OSError as e:
        return "", str(e), -1


def run_bandit(
    repo_root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
) -> ToolResult:
    if not _check_installed("bandit"):
        return ToolResult(tool="bandit", available=False)

    args = ["bandit", "-f", "json", "-r"]
    if scope:
        for s in scope:
            target = repo_root / s
            if target.exists():
                args.append(str(target))
    else:
        args.append(str(repo_root))

    exclude_dirs = exclude or []
    bandit_excludes = []
    for exc in exclude_dirs:
        exc_path = repo_root / exc.rstrip("/")
        if exc_path.is_dir():
            bandit_excludes.append(str(exc_path))
    if bandit_excludes:
        args.extend(["--exclude", ",".join(bandit_excludes)])

    stdout, stderr, returncode = _run_command(args, cwd=repo_root)
    if returncode not in (0, 1):
        return ToolResult(tool="bandit", available=True, error=stderr or f"bandit exited with code {returncode}")

    idx = stdout.find("{")
    raw_json = stdout[idx:] if idx >= 0 else stdout
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return ToolResult(tool="bandit", available=True, error=f"Failed to parse bandit JSON: {e}", raw_output=raw_json[:500])

    findings: list[Finding] = []
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    _TEST_NOISE = {"B101"}

    def _is_test(path: str) -> bool:
        parts = Path(path).parts
        return "tests" in parts or any(p.startswith("test_") for p in parts)

    for r in data.get("results", []):
        sev = r.get("issue_severity", "LOW")
        conf = r.get("issue_confidence", "LOW")
        rule_id = r.get("test_id", "")
        filename = r.get("filename", "")
        if rule_id in _TEST_NOISE and _is_test(filename):
            continue
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        findings.append(Finding(rule_id=rule_id, severity=sev, confidence=conf,
                                message=r.get("issue_text", ""), file=filename,
                                line=r.get("line_number", 0), tool="bandit"))

    metrics = data.get("metrics", {})
    total_loc = sum(v.get("loc", 0) for v in metrics.values() if isinstance(v, dict))
    weighted = severity_counts["HIGH"] * 3 + severity_counts["MEDIUM"] * 2 + severity_counts["LOW"]
    kloc = max(total_loc / 1000, 0.1)

    return ToolResult(tool="bandit", available=True, findings=findings,
                      metrics={"total_findings": len(findings), "high_severity": severity_counts["HIGH"],
                               "medium_severity": severity_counts["MEDIUM"], "low_severity": severity_counts["LOW"],
                               "weighted_findings": weighted, "weighted_per_kloc": weighted / kloc, "total_loc": total_loc})


def run_radon(
    repo_root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
) -> ToolResult:
    if not _check_installed("radon"):
        return ToolResult(tool="radon", available=False)

    targets = []
    if scope:
        for s in scope:
            target = repo_root / s
            if target.exists():
                targets.append(str(target))
    targets = targets or [str(repo_root)]

    exclude_args: list[str] = []
    if exclude:
        patterns = [exc.rstrip("/") + "/*" for exc in exclude]
        exclude_args = ["-e", ",".join(patterns)]

    cc_args = ["radon", "cc", "-j", "-s", "-a"] + exclude_args + targets
    cc_stdout, cc_stderr, cc_rc = _run_command(cc_args, cwd=repo_root)
    cc_data: dict | str = cc_stderr or f"radon cc exited with code {cc_rc}" if cc_rc != 0 else cc_stdout
    if isinstance(cc_data, str) and cc_rc == 0:
        try:
            cc_data = json.loads(cc_data)
        except json.JSONDecodeError as e:
            cc_data = f"Failed to parse radon cc JSON: {e}"

    mi_args = ["radon", "mi", "-j", "-s"] + exclude_args + targets
    mi_stdout, mi_stderr, mi_rc = _run_command(mi_args, cwd=repo_root)
    mi_data: dict | str = mi_stderr or f"radon mi exited with code {mi_rc}" if mi_rc != 0 else mi_stdout
    if isinstance(mi_data, str) and mi_rc == 0:
        try:
            mi_data = json.loads(mi_data)
        except json.JSONDecodeError as e:
            mi_data = f"Failed to parse radon mi JSON: {e}"

    errors = []
    if isinstance(cc_data, str):
        errors.append(cc_data)
        cc_data = {}
    if isinstance(mi_data, str):
        errors.append(mi_data)
        mi_data = {}

    if errors and not cc_data and not mi_data:
        return ToolResult(tool="radon", available=True, error="; ".join(errors))

    findings: list[Finding] = []
    complexities: list[int] = []
    rank_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "F": 0}

    def _rank_to_sev(rank: str) -> str:
        return "HIGH" if rank in ("E", "F") else "MEDIUM" if rank in ("C", "D") else "LOW"

    for file_path, functions in cc_data.items():
        if not isinstance(functions, list):
            continue
        for func in functions:
            complexity = func.get("complexity", 0)
            rank = func.get("rank", "A")
            complexities.append(complexity)
            rank_counts[rank] = rank_counts.get(rank, 0) + 1
            if rank not in ("A", "B"):
                findings.append(Finding(
                    rule_id=f"CC:{rank}", severity=_rank_to_sev(rank), confidence="HIGH",
                    message=f"{func.get('type', 'function')} '{func.get('name', '?')}' has cyclomatic complexity {complexity} (rank {rank})",
                    file=file_path, line=func.get("lineno", 0), tool="radon"))

    mi_scores: list[float] = []
    for file_path, mi_info in mi_data.items():
        if isinstance(mi_info, dict):
            mi_scores.append(mi_info.get("mi", 0.0))

    radon_metrics: dict[str, float] = {"total_functions": len(complexities)}
    if complexities:
        sorted_cc = sorted(complexities)
        p90_idx = min(int(len(sorted_cc) * 0.9), len(sorted_cc) - 1)
        radon_metrics["avg_complexity"] = sum(complexities) / len(complexities)
        radon_metrics["max_complexity"] = max(complexities)
        radon_metrics["p90_complexity"] = sorted_cc[p90_idx]
    for rank, count in rank_counts.items():
        radon_metrics[f"rank_{rank}"] = count
    simple = rank_counts.get("A", 0) + rank_counts.get("B", 0)
    radon_metrics["simple_ratio"] = simple / len(complexities) if complexities else 1.0
    if mi_scores:
        radon_metrics["avg_mi"] = sum(mi_scores) / len(mi_scores)
        radon_metrics["min_mi"] = min(mi_scores)

    return ToolResult(tool="radon", available=True, findings=findings,
                      metrics=radon_metrics, error="; ".join(errors) if errors else "")


# -- Dimension Scorers -------------------------------------------------------


def _source_files(project: ProjectAnalysis) -> list[FileAnalysis]:
    return [f for f in project.files if "/tests/" not in f.path and not f.path.startswith("tests/")]


def score_maintainability(project: ProjectAnalysis, tool_results: dict[str, ToolResult] | None = None) -> DimensionScore:
    tool_results = tool_results or {}
    source = _source_files(project)
    total_callables = sum(f.total_callables for f in source)
    documented = sum(f.documented_callables for f in source)
    doc_coverage = ratio_score(documented, total_callables)
    if source:
        sizes = sorted(f.lines for f in source)
        p90_size = sizes[min(int(len(sizes) * 0.9), len(sizes) - 1)]
        file_size_score = inverse_linear(p90_size, good=200, bad=800)
    else:
        p90_size = 0
        file_size_score = 100.0
    all_lengths: list[int] = []
    for f in source:
        all_lengths.extend(f.function_lengths)
    if all_lengths:
        p90_length = sorted(all_lengths)[min(int(len(all_lengths) * 0.9), len(all_lengths) - 1)]
        func_length_score = inverse_linear(p90_length, good=30, bad=100)
    else:
        p90_length = 0
        func_length_score = 100.0
    sub_scores = {"doc_coverage": doc_coverage, "file_size_p90": file_size_score, "function_length_p90": func_length_score}
    recommendations: list[str] = []
    radon = tool_results.get("radon")
    if radon and radon.success:
        avg_mi = radon.metrics.get("avg_mi", 50.0)
        mi_score = min(100.0, max(0.0, avg_mi))
        sub_scores["radon_mi"] = mi_score
        score = doc_coverage * 0.25 + file_size_score * 0.20 + func_length_score * 0.25 + mi_score * 0.30
        if avg_mi < 40:
            recommendations.append(f"Average maintainability index is {avg_mi:.0f} -- refactor complex modules")
    else:
        if source:
            avg_funcs = statistics.mean(f.functions for f in source)
            cohesion_score = sigmoid(avg_funcs, midpoint=15, k=0.2)
        else:
            cohesion_score = 100.0
        sub_scores["cohesion"] = cohesion_score
        score = doc_coverage * 0.30 + file_size_score * 0.25 + func_length_score * 0.25 + cohesion_score * 0.20
    if doc_coverage < 50:
        recommendations.append(f"Documentation coverage is {doc_coverage:.0f}% -- add docstrings")
    if p90_size > 500:
        recommendations.append(f"P90 file size is {p90_size} lines -- split large files")
    if p90_length > 50:
        recommendations.append(f"P90 function length is {p90_length} lines -- extract helpers")
    return DimensionScore(name="Maintainability", score=score, sub_scores=sub_scores, recommendations=recommendations)


def score_security(project: ProjectAnalysis, tool_results: dict[str, ToolResult] | None = None) -> DimensionScore:
    tool_results = tool_results or {}
    source = _source_files(project)
    kloc = max(project.source_lines / 1000, 0.1)
    total_unsafe = sum(len(f.unsafe_calls) for f in source)
    unsafe_per_kloc = total_unsafe / kloc
    ast_unsafe_score = exp_decay(unsafe_per_kloc, rate=1.0)
    files_with_unsafe = sum(1 for f in source if f.unsafe_calls)
    ast_clean_ratio = ratio_score(len(source) - files_with_unsafe, len(source)) if source else 100.0
    sub_scores = {"ast_unsafe_patterns": ast_unsafe_score, "ast_clean_file_ratio": ast_clean_ratio}
    recommendations: list[str] = []
    confidence = 0.5
    bandit = tool_results.get("bandit")
    if bandit and bandit.success:
        confidence = 0.9
        m = bandit.metrics
        bandit_density = exp_decay(m.get("weighted_per_kloc", 0), rate=0.3)
        bandit_high = exp_decay(int(m.get("high_severity", 0)), rate=1.5)
        bandit_med = exp_decay(int(m.get("medium_severity", 0)), rate=0.5)
        sub_scores.update({"bandit_severity_density": bandit_density, "bandit_high_severity": bandit_high, "bandit_medium_severity": bandit_med})
        score = bandit_density * 0.30 + bandit_high * 0.25 + bandit_med * 0.15 + ast_unsafe_score * 0.15 + ast_clean_ratio * 0.15
        if int(m.get("high_severity", 0)) > 0:
            recommendations.append(f"{int(m['high_severity'])} HIGH severity finding(s) -- fix immediately")
        if int(m.get("medium_severity", 0)) > 0:
            recommendations.append(f"{int(m['medium_severity'])} MEDIUM severity finding(s)")
    else:
        score = ast_unsafe_score * 0.60 + ast_clean_ratio * 0.40
        if not bandit:
            recommendations.append("Install bandit for deeper security analysis: pip install bandit")
    return DimensionScore(name="Security", score=score, sub_scores=sub_scores, confidence=confidence, recommendations=recommendations)


def score_modularity(project: ProjectAnalysis, code_map: dict | None = None) -> DimensionScore:
    if not code_map:
        return DimensionScore(name="Modularity", score=50.0, confidence=0.3,
                              recommendations=["Run with --no-skip-code-map for accurate modularity scoring"])
    graph = code_map.get("import_graph", {})
    ce = {m: len(deps) for m, deps in graph.items()}
    ca: dict[str, int] = {}
    for targets in graph.values():
        for t in targets:
            ca[t] = ca.get(t, 0) + 1
    all_modules = set(ce.keys()) | set(ca.keys())
    instabilities = []
    for m in all_modules:
        c_e = ce.get(m, 0)
        c_a = ca.get(m, 0)
        if c_e + c_a > 0:
            instabilities.append(c_e / (c_e + c_a))
    instability_score = 100.0 * (1.0 - abs(statistics.mean(instabilities) - 0.5) * 2) if instabilities else 50.0
    max_ce = max(ce.values()) if ce else 0
    coupling_score = sigmoid(max_ce, midpoint=15, k=0.3)
    cycle_count = _count_cycles(graph)
    cycle_score = exp_decay(cycle_count, rate=1.0)
    modules_data = code_map.get("modules", {})
    sizes = [m.get("lines", 0) for m in modules_data.values()]
    gini = _gini_coefficient(sizes) if len(sizes) > 1 else 0.0
    gini_score = (1.0 - gini) * 100.0 if len(sizes) > 1 else 100.0
    score = instability_score * 0.25 + coupling_score * 0.30 + cycle_score * 0.25 + gini_score * 0.20
    recommendations = []
    if max_ce > 15:
        worst = max(ce, key=ce.get)
        recommendations.append(f"{worst} has Ce={max_ce} -- too many dependencies")
    if cycle_count > 0:
        recommendations.append(f"{cycle_count} circular dependency(ies) -- break with protocols")
    return DimensionScore(name="Modularity", score=score, sub_scores={"instability_balance": instability_score, "coupling_max_ce": coupling_score, "circular_deps": cycle_score, "size_gini": gini_score}, recommendations=recommendations)


def score_testability(project: ProjectAnalysis, tool_results: dict[str, ToolResult] | None = None) -> DimensionScore:
    tool_results = tool_results or {}
    test_ratio = project.test_lines / project.source_lines if project.source_lines > 0 else 0.0
    ratio_score_val = sigmoid(abs(test_ratio - 1.0), midpoint=0.8, k=3.0) if project.source_lines > 0 else 0.0
    file_ratio = project.test_files / project.source_files if project.source_files > 0 else 0.0
    file_ratio_score = min(100.0, file_ratio * 100.0)
    source = _source_files(project)
    max_nestings = [f.max_nesting for f in source if f.max_nesting > 0]
    nesting_score = sigmoid(statistics.mean(max_nestings), midpoint=4, k=1.0) if max_nestings else 100.0
    sub_scores = {"test_code_ratio": ratio_score_val, "test_file_ratio": file_ratio_score, "avg_nesting_depth": nesting_score}
    recommendations: list[str] = []
    radon = tool_results.get("radon")
    if radon and radon.success:
        avg_cc = radon.metrics.get("avg_complexity", 5.0)
        complexity_score = sigmoid(avg_cc, midpoint=10, k=0.3)
        simple_score = radon.metrics.get("simple_ratio", 1.0) * 100.0
        sub_scores.update({"radon_avg_complexity": complexity_score, "simple_function_ratio": simple_score})
        score = ratio_score_val * 0.30 + file_ratio_score * 0.15 + complexity_score * 0.25 + simple_score * 0.15 + nesting_score * 0.15
    else:
        all_lengths = [l for f in source for l in f.function_lengths]
        length_score = sigmoid(statistics.mean(all_lengths), midpoint=25, k=0.15) if all_lengths else 100.0
        sub_scores["avg_function_length"] = length_score
        score = ratio_score_val * 0.35 + file_ratio_score * 0.20 + length_score * 0.25 + nesting_score * 0.20
    if test_ratio < 0.5:
        recommendations.append(f"Test-to-code ratio is {test_ratio:.2f} -- aim for 0.8-1.2")
    if project.test_files == 0:
        recommendations.append("No test files found")
    return DimensionScore(name="Testability", score=score, sub_scores=sub_scores, recommendations=recommendations)


def score_robustness(project: ProjectAnalysis) -> DimensionScore:
    source = _source_files(project)
    param_coverage = ratio_score(sum(f.annotated_params for f in source), sum(f.total_params for f in source))
    return_coverage = ratio_score(sum(f.annotated_returns for f in source), sum(f.total_returns for f in source))
    total_handlers = sum(f.exception_handlers for f in source)
    bad_handlers = sum(f.bare_excepts for f in source) + sum(f.broad_excepts for f in source)
    handler_quality = (1.0 - bad_handlers / total_handlers) * 100.0 if total_handlers > 0 else 100.0
    score = param_coverage * 0.35 + return_coverage * 0.30 + handler_quality * 0.35
    recommendations = []
    if param_coverage < 70:
        recommendations.append(f"Parameter type coverage is {param_coverage:.0f}% -- add annotations")
    if return_coverage < 70:
        recommendations.append(f"Return type coverage is {return_coverage:.0f}% -- add return types")
    if sum(f.bare_excepts for f in source) > 0:
        recommendations.append(f"{sum(f.bare_excepts for f in source)} bare/swallowed except(s)")
    return DimensionScore(name="Robustness", score=score, sub_scores={"param_type_coverage": param_coverage, "return_type_coverage": return_coverage, "exception_handling_quality": handler_quality}, recommendations=recommendations)


def score_elegance(project: ProjectAnalysis, tool_results: dict[str, ToolResult] | None = None) -> DimensionScore:
    tool_results = tool_results or {}
    source = _source_files(project)
    nestings = [f.max_nesting for f in source]
    if nestings:
        p90_nesting = sorted(nestings)[min(int(len(nestings) * 0.9), len(nestings) - 1)]
        nesting_score = sigmoid(p90_nesting, midpoint=4, k=1.5)
    else:
        p90_nesting = 0
        nesting_score = 100.0
    all_lengths = [l for f in source for l in f.function_lengths]
    if all_lengths:
        p90_length = sorted(all_lengths)[min(int(len(all_lengths) * 0.9), len(all_lengths) - 1)]
        length_score = inverse_linear(p90_length, good=30, bad=100)
    else:
        p90_length = 0
        length_score = 100.0
    total_defs = sum(f.functions + f.classes for f in source)
    total_violations = sum(f.naming_violations for f in source)
    naming_score = (1.0 - total_violations / total_defs) * 100.0 if total_defs > 0 else 100.0
    sub_scores = {"nesting_depth_p90": nesting_score, "function_length_p90": length_score, "naming_conventions": naming_score}
    recommendations: list[str] = []
    radon = tool_results.get("radon")
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
    return DimensionScore(name="Elegance", score=score, sub_scores=sub_scores, recommendations=recommendations)


def score_reusability(project: ProjectAnalysis, code_map: dict | None = None) -> DimensionScore:
    source = _source_files(project)
    total_public = sum(f.public_definitions for f in source)
    total_private = sum(f.private_definitions for f in source)
    total_defs = total_public + total_private
    if total_defs > 0:
        api_ratio = total_public / total_defs
        api_score = 100.0 if 0.3 <= api_ratio <= 0.6 else (api_ratio / 0.3 * 100.0 if api_ratio < 0.3 else max(0.0, 100.0 - (api_ratio - 0.6) / 0.4 * 100.0))
    else:
        api_ratio = 0.0
        api_score = 50.0
    if code_map:
        graph = code_map.get("import_graph", {})
        ce_values = [len(deps) for deps in graph.values()]
        coupling_score = sigmoid(statistics.mean(ce_values), midpoint=8, k=0.4) if ce_values else 100.0
    else:
        coupling_score = 50.0
    size_score = sigmoid(statistics.mean(f.lines for f in source), midpoint=200, k=0.02) if source else 50.0
    score = api_score * 0.35 + coupling_score * 0.35 + size_score * 0.30
    recommendations = []
    if total_defs > 0 and api_ratio > 0.7:
        recommendations.append(f"API surface is {api_ratio:.0%} public -- consider making more internals private")
    return DimensionScore(name="Reusability", score=score, sub_scores={"api_surface_ratio": api_score, "coupling": coupling_score, "module_size": size_score}, recommendations=recommendations)


# -- Composite PQI -----------------------------------------------------------

CRITICAL_FLOOR = 20


def compute_pqi(dimensions: dict[str, DimensionScore], profile: str = "production", file_count: int = 0, line_count: int = 0) -> PQIResult:
    weights = WEIGHT_PROFILES.get(profile, WEIGHT_PROFILES["production"])
    scores = {k: max(1.0, v.score) for k, v in dimensions.items()}
    log_sum = sum(w * math.log(scores.get(d, 50.0)) for d, w in weights.items())
    geometric_mean = math.exp(log_sum)
    penalty = _floor_penalty(scores)
    composite = min(100.0, geometric_mean * penalty)
    return PQIResult(composite=round(composite, 1), dimensions=dimensions, quality_band=classify_band(composite), floor_penalty=round(penalty, 3), file_count=file_count, line_count=line_count)


def _floor_penalty(dimension_scores: dict[str, float]) -> float:
    violations = [s for s in dimension_scores.values() if s < CRITICAL_FLOOR]
    if not violations:
        return 1.0
    penalty = 1.0
    for s in violations:
        deficit = (CRITICAL_FLOOR - s) / CRITICAL_FLOOR
        penalty *= (1.0 - 0.3 * deficit)
    return max(0.3, penalty)


# -- Helpers -----------------------------------------------------------------


def _count_cycles(graph: dict[str, list[str]]) -> int:
    visited: set[str] = set()
    rec_stack: set[str] = set()
    cycles = 0

    def dfs(node: str) -> None:
        nonlocal cycles
        visited.add(node)
        rec_stack.add(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                dfs(neighbor)
            elif neighbor in rec_stack:
                cycles += 1
        rec_stack.discard(node)

    for node in graph:
        if node not in visited:
            dfs(node)
    return cycles


def _gini_coefficient(values: list[int | float]) -> float:
    if not values or len(values) < 2:
        return 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    total = sum(sorted_vals)
    if total == 0:
        return 0.0
    cumulative = sum((2 * (i + 1) - n - 1) * v for i, v in enumerate(sorted_vals))
    return cumulative / (n * total)


# -- Scorer (orchestrator) ---------------------------------------------------


def score_project(
    repo_root: Path,
    scope: list[str] | None = None,
    exclude: list[str] | None = None,
    code_map: dict | None = None,
    profile: str = "production",
    tools: list[str] | None = None,
) -> PQIResult:
    project = analyze_project(repo_root, scope=scope, exclude=exclude)
    tool_results: dict[str, ToolResult] = {}
    for name in (tools or []):
        if name == "bandit":
            tool_results["bandit"] = run_bandit(repo_root, scope, exclude)
        elif name == "radon":
            tool_results["radon"] = run_radon(repo_root, scope, exclude)
    dimensions = {
        "maintainability": score_maintainability(project, tool_results),
        "security": score_security(project, tool_results),
        "modularity": score_modularity(project, code_map),
        "testability": score_testability(project, tool_results),
        "robustness": score_robustness(project),
        "elegance": score_elegance(project, tool_results),
        "reusability": score_reusability(project, code_map),
    }
    result = compute_pqi(dimensions, profile=profile, file_count=project.source_files, line_count=project.source_lines)
    return result


# -- CLI Output --------------------------------------------------------------


def _score_bar(score: float, width: int = 40) -> str:
    filled = int(score / 100 * width)
    return f"  [{'#' * filled}{'.' * (width - filled)}] {score:.1f}%"


def _mini_bar(score: float, width: int = 20) -> str:
    filled = int(score / 100 * width)
    return f"{'#' * filled}{'.' * (width - filled)}"


def _print_report(result: PQIResult, show_recommendations: bool = False) -> None:
    band = result.quality_band.value
    bar = _score_bar(result.composite)
    print(f"\n{'=' * 60}")
    print(f"  PyQuality Index (PQI)")
    print(f"{'=' * 60}")
    print(f"\n  Composite Score:  {result.composite:.1f} / 100  [{band}]")
    print(f"  {bar}")
    print(f"\n  Files: {result.file_count}    Lines: {result.line_count:,}")
    if result.floor_penalty < 1.0:
        print(f"  Floor penalty: {result.floor_penalty:.3f}")
    print(f"\n{'-' * 60}")
    print(f"  {'Dimension':<20} {'Score':>6}  {'Bar'}")
    print(f"{'-' * 60}")
    for name, dim in sorted(result.dimensions.items(), key=lambda x: x[1].score, reverse=True):
        bar = _mini_bar(dim.score)
        confidence = f" (confidence: {dim.confidence:.0%})" if dim.confidence < 1.0 else ""
        print(f"  {dim.name:<20} {dim.score:>5.1f}  {bar}{confidence}")
        if show_recommendations:
            for sub_name, sub_score in dim.sub_scores.items():
                print(f"    {sub_name:<22} {sub_score:>5.1f}")
    if show_recommendations:
        print(f"\n{'-' * 60}")
        print("  Recommendations")
        print(f"{'-' * 60}")
        for name, dim in sorted(result.dimensions.items(), key=lambda x: x[1].score):
            if dim.recommendations:
                print(f"\n  [{dim.name}]")
                for rec in dim.recommendations:
                    print(f"    - {rec}")
    print(f"\n{'=' * 60}\n")


def _result_to_dict(result: PQIResult) -> dict:
    return {
        "composite": result.composite,
        "quality_band": result.quality_band.value,
        "floor_penalty": result.floor_penalty,
        "file_count": result.file_count,
        "line_count": result.line_count,
        "dimensions": {
            name: {"name": dim.name, "score": round(dim.score, 1), "sub_scores": {k: round(v, 1) for k, v in dim.sub_scores.items()}, "confidence": dim.confidence, "recommendations": dim.recommendations}
            for name, dim in result.dimensions.items()
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score codebase quality using the PyQuality Index (PQI).")
    parser.add_argument("--scope", nargs="*", default=["src/", "tests/"], help="Directories to include")
    parser.add_argument("--exclude", nargs="*", default=["__pycache__/"], help="Patterns to exclude")
    parser.add_argument("--profile", choices=list(WEIGHT_PROFILES.keys()), default="safety_critical", help="Weight profile (default: safety_critical)")
    parser.add_argument("--no-code-map", action="store_true", help="Skip code map for modularity scoring")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    parser.add_argument("--recommendations", action="store_true", help="Show actionable recommendations")
    parser.add_argument("--no-bandit", action="store_true", help="Skip Bandit security linter")
    parser.add_argument("--no-radon", action="store_true", help="Skip Radon complexity analyzer")
    parser.add_argument("--output", "-o", type=str, default=None, help="Write output to file")
    parser.add_argument("--stdout", action="store_true", help="Print to stdout instead of .codemap/")
    args = parser.parse_args()

    exclude = args.exclude or [".venv/", "__pycache__/", ".git/", ".mypy_cache/", ".pytest_cache/", ".ruff_cache/"]

    code_map = None
    if not args.no_code_map:
        sys.path.insert(0, str(PROJECT_ROOT))
        from scripts.code_map import generate_code_map
        code_map = generate_code_map(repo_root=PROJECT_ROOT, scope=args.scope, exclude=exclude)

    tools = []
    if not args.no_bandit:
        tools.append("bandit")
    if not args.no_radon:
        tools.append("radon")

    result = score_project(repo_root=PROJECT_ROOT, scope=args.scope, exclude=exclude, code_map=code_map, profile=args.profile, tools=tools)

    _print_report(result, show_recommendations=args.recommendations)

    if args.json_output:
        output = json.dumps(_result_to_dict(result), indent=2)
    else:
        output = json.dumps(_result_to_dict(result), indent=2)

    if args.stdout:
        print(output)
        return

    if args.output:
        out_path = Path(args.output)
    else:
        codemap_dir = PROJECT_ROOT / ".codemap"
        codemap_dir.mkdir(exist_ok=True)
        out_path = codemap_dir / "quality.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output, encoding="utf-8")
    print(f"Quality report written to {out_path}")


if __name__ == "__main__":
    main()
